from bomsquad.vulndb.db.connection import instance as factory


class TestConnectionFactory:
    def test_get_closed(self) -> None:
        factory.close()
        with factory.get() as conn:
            assert conn

    def test_is_open(self) -> None:
        factory.close()
        assert factory.is_open() is False
        with factory.get():
            assert factory.is_open()

    def test_close(self) -> None:
        with factory.get():
            assert factory.is_open()
        factory.close()
        assert factory.is_open() is False
