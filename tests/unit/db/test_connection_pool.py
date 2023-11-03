from bomsquad.vulndb.db.connection import pool


class TestConnectionPool:
    def test_get_closed(self) -> None:
        pool.close()
        with pool.get() as conn:
            assert conn

    def test_is_open(self) -> None:
        pool.close()
        assert pool.is_open() is False
        with pool.get():
            assert pool.is_open()

    def test_close(self) -> None:
        with pool.get():
            assert pool.is_open()
        pool.close()
        assert pool.is_open() is False
