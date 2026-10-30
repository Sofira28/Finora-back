"""Pruebas del tipo Money (T-SETUP-BE-02, CA-SETUP-03, VAL-SETUP-01/02)."""

from decimal import Decimal

import pytest
from hypothesis import given
from hypothesis import strategies as st

from finora.domain.money import CurrencyMismatchError, Money

amounts = st.decimals(
    min_value=Decimal("-1e14"), max_value=Decimal("1e14"), places=4, allow_nan=False
)


class TestConstruccion:
    def test_acepta_decimal_int_y_cadena(self) -> None:
        assert Money(Decimal("10.50"), "COP").amount == Decimal("10.50")
        assert Money(10, "COP").amount == Decimal(10)
        assert Money("0.1", "COP").amount == Decimal("0.1")

    @pytest.mark.parametrize("valor", [0.1, 1.0, True, None, [1]])
    def test_rechaza_float_bool_y_otros(self, valor: object) -> None:
        with pytest.raises(TypeError):
            Money(valor, "COP")  # type: ignore[arg-type]

    @pytest.mark.parametrize("valor", ["abc", "", "NaN", "Infinity", Decimal("-inf")])
    def test_rechaza_cadenas_invalidas_y_no_finitos(self, valor: str | Decimal) -> None:
        with pytest.raises(ValueError):
            Money(valor, "COP")

    @pytest.mark.parametrize("moneda", ["USD", "cop", "", "PESOS"])
    def test_rechaza_monedas_no_soportadas(self, moneda: str) -> None:
        with pytest.raises(ValueError):
            Money(1, moneda)

    def test_es_inmutable(self) -> None:
        m = Money(1, "COP")
        with pytest.raises(AttributeError):
            m.amount = Decimal(2)  # type: ignore[misc]


class TestRedondeo:
    @pytest.mark.parametrize(
        ("entrada", "esperado"),
        [
            ("0.125", "0.12"),  # punto medio, par hacia abajo
            ("0.135", "0.14"),  # punto medio, par hacia arriba
            ("0.126", "0.13"),
            ("-0.125", "-0.12"),
            ("-0.135", "-0.14"),
        ],
    )
    def test_half_even_a_dos_decimales(self, entrada: str, esperado: str) -> None:
        assert Money(entrada, "COP").rounded(2).amount == Decimal(esperado)

    @pytest.mark.parametrize(
        ("entrada", "esperado"),
        [("1234567.5", "1234568"), ("1234566.5", "1234566"), ("2.5", "2"), ("3.5", "4")],
    )
    def test_half_even_a_pesos_enteros(self, entrada: str, esperado: str) -> None:
        assert Money(entrada, "COP").rounded(0).amount == Decimal(esperado)

    def test_places_negativo_falla(self) -> None:
        with pytest.raises(ValueError):
            Money(1, "COP").rounded(-1)

    def test_for_storage_usa_cuatro_decimales(self) -> None:
        assert Money("1.00005", "COP").for_storage().amount == Decimal("1.0000")
        assert Money("1.00015", "COP").for_storage().amount == Decimal("1.0002")

    def test_for_storage_fuera_de_rango(self) -> None:
        with pytest.raises(ValueError):
            Money("1e15", "COP").for_storage()

    @given(amounts.map(lambda d: d * Decimal("1.37")), st.integers(min_value=0, max_value=4))
    def test_error_de_redondeo_acotado(self, valor: Decimal, places: int) -> None:
        redondeado = Money(valor, "COP").rounded(places).amount
        assert abs(redondeado - valor) <= Decimal(1).scaleb(-places) / 2

    @given(amounts, st.integers(min_value=0, max_value=4))
    def test_redondeo_idempotente(self, valor: Decimal, places: int) -> None:
        una = Money(valor, "COP").rounded(places)
        assert una.rounded(places) == una


class TestAritmetica:
    def test_suma_exacta_sin_error_de_punto_flotante(self) -> None:
        assert Money("0.1", "COP") + Money("0.2", "COP") == Money("0.3", "COP")

    def test_resta_produce_saldo_negativo(self) -> None:
        saldo = Money(50_000, "COP") - Money(80_000, "COP")
        assert saldo == Money(-30_000, "COP")
        assert saldo.is_negative()

    def test_negacion_y_multiplicacion(self) -> None:
        assert -Money(5, "COP") == Money(-5, "COP")
        assert Money("100", "COP") * Decimal("0.19") == Money("19.00", "COP")
        assert 3 * Money("100", "COP") == Money(300, "COP")

    def test_multiplicar_por_float_falla(self) -> None:
        with pytest.raises(TypeError):
            Money(1, "COP") * 0.5  # type: ignore[operator]

    def test_comparaciones(self) -> None:
        assert Money(1, "COP") < Money(2, "COP") <= Money(2, "COP")
        assert Money(3, "COP") > Money(2, "COP") >= Money(2, "COP")

    def test_igualdad_por_valor(self) -> None:
        assert Money("1.0", "COP") == Money("1.00", "COP")
        assert hash(Money("1.0", "COP")) == hash(Money("1.00", "COP"))

    def test_monedas_distintas_fallan(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("finora.domain.money.SUPPORTED_CURRENCIES", frozenset({"COP", "USD"}))
        cop, usd = Money(1, "COP"), Money(1, "USD")
        with pytest.raises(CurrencyMismatchError):
            cop + usd
        with pytest.raises(CurrencyMismatchError):
            cop - usd
        with pytest.raises(CurrencyMismatchError):
            _ = cop < usd

    @given(amounts, amounts, amounts)
    def test_suma_asociativa_y_conmutativa(self, a: Decimal, b: Decimal, c: Decimal) -> None:
        ma, mb, mc = Money(a, "COP"), Money(b, "COP"), Money(c, "COP")
        assert (ma + mb) + mc == ma + (mb + mc)
        assert ma + mb == mb + ma

    @given(amounts, amounts)
    def test_resta_inversa_de_suma(self, a: Decimal, b: Decimal) -> None:
        ma, mb = Money(a, "COP"), Money(b, "COP")
        assert (ma + mb) - mb == ma

    def test_zero(self) -> None:
        assert Money.zero("COP") == Money(0, "COP")


class TestSerializacion:
    @pytest.mark.parametrize(
        ("entrada", "esperado"),
        [("125000.00", "125000.00"), ("1E+6", "1000000"), ("-0.5", "-0.5")],
    )
    def test_to_api_string_sin_notacion_cientifica(self, entrada: str, esperado: str) -> None:
        assert Money(entrada, "COP").to_api_string() == esperado
