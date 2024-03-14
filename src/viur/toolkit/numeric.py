__all__ = ["round_decimal", "format_currency"]


def round_decimal(value: float, frac_digits: int = 2) -> float:
    """Round decimal correctly, even as floating-point"""
    return round(value * (10 ** frac_digits), 0) / (10 ** frac_digits)


def format_currency(value: float, frac_digits: int = 2) -> str:
    before, after = "{:,.2f}".format(round_decimal(value, frac_digits)).split(".")
    before = before.replace(",", ".")
    return f"{before},{after}"
