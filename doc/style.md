# Coding Style

The coding style should follow [NumPy coding style guide](https://numpydoc.readthedocs.io/en/latest/format.html)

## Documentation

```python
class MyClass(MyParent):
    """Brief

    Details

    Attributes
    ----------
    x : int
        Description
    y : str
        Description
    """

    def my_method(self,
        param1: int, *,
        param2: str = '',
        param3: Callable|None = None
    ) -> dict[str, int]:
        """A Brief description

        Parameters
        ----------
        param1 : int
            Description of `param1`
        param2 : str, default=''
            Description of `param2`
        param3 : function like, optional
            Description of `param3`

        Returns
        -------
        dict[str, int]
            Description

        Raises
        ------
        BrokenPipeError
            Description
        """
```

Further sections: Yields (generators), Receives (via send)

## Quotes

douple quotes: use for natural text, string interpolation, quotations
Single quotes: ID and code related string literals
