from deprecated import deprecated

__all__ = [
    "round_decimal",
    "format_number",
    "format_currency",
]


def round_decimal(value: float, frac_digits: int = 2) -> float:
    """Round decimal correctly, even as floating-point"""
    return round(value * (10 ** frac_digits), 0) / (10 ** frac_digits)


def format_number(value: float, frac_digits: int = 2, thousands_separator: str = "") -> str:
    """
    Format a floating-point number with a specified number of fractional digits
    and an optional custom thousands separator.

    The function formats the given number using thousands separators and the specified
    number of digits after the decimal point. If a custom thousands separator is provided,
    it's used in the integer part.

    :param value: The number to format.
    :param frac_digits: Number of digits to display after the decimal point. Defaults to 2.
    :param thousands_separator: Custom character to use as the thousands separator.
        If empty, no thousands separator is used.
    :return: The formatted number as a string.
    """
    format_str = "{{:,.{}f}}".format(frac_digits)
    number_str = format_str.format(value)
    if frac_digits > 0:
        before, after = number_str.split(".")
        before = before.replace(",", thousands_separator)
        return f"{before},{after}"
    return number_str.replace(",", thousands_separator)


format_currency = deprecated(  # type: ignore
    format_number,
    reason="format_currency has been renamed to format_number",
    version="0.5.0",
)
