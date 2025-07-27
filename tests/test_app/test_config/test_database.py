# """Tests for database configuration and connection management."""
#
# import pytest
# import asyncio
# from unittest.mock import patch, AsyncMock, MagicMock
# from sqlalchemy.ext.asyncio import AsyncSession, AsyncEngine
# from sqlalchemy.exc import SQLAlchemyError, OperationalError
# from sqlalchemy import text
#
# from app.config.database import (
#     DatabaseManager,
#     get_database_manager,
#     get_async_session,
#     create_database_engine,
#     check_database_connection,
#     init_database
# )
# from app.config.settings import Settings
#
#
# class TestDatabaseManager:
#     """Test DatabaseManager class."""
#
#     @pytest.fixture
#     def mock_settings(self):
#         """Mock settings for testing."""
#         settings = MagicMock(spec=Settings)
#         settings.database_url = "postgresql+asyncpg://test:test@localhost:5432/test_db"
#         settings.is_testing = False
#         settings.debug = False
#         return settings
#
#     @pytest.fixture
#     def database_manager(self, mock_settings):
#         """Create DatabaseManager instance for testing."""
#         return DatabaseManager(mock_settings)
#
#     def test_database_manager_initialization(self, mock_settings):
#         """Test DatabaseManager initialization."""
#         manager = DatabaseManager(mock_settings)
#
#         assert manager.settings == mock_settings
#         assert manager._engine is None
#         assert manager._session_factory is None
#
#     def test_database_manager_engine_property(self, database_manager, mock_settings):
#         """Test engine property lazy initialization."""
#         with patch('app.config.database.create_async_engine') as mock_create_engine:
#             mock_engine = MagicMock()
#             mock_create_engine.return_value = mock_engine
#
#             # First access should create engine
#             engine = database_manager.engine
#
#             assert engine == mock_engine
#             mock_create_engine.assert_called_once()
#
#             # Second access should return cached engine
#             engine2 = database_manager.engine
#             assert engine2 == mock_engine
#             assert mock_create_engine.call_count == 1
#
#     def test_database_manager_session_factory_property(self, database_manager):
#         """Test session_factory property lazy initialization."""
#         with patch('app.config.database.async_sessionmaker') as mock_sessionmaker:
#             mock_factory = MagicMock()
#             mock_sessionmaker.return_value = mock_factory
#
#             # Mock the engine property
#             with patch.object(database_manager, 'engine', MagicMock()):
#                 # First access should create session factory
#                 factory = database_manager.session_factory
#
#                 assert factory == mock_factory
#                 mock_sessionmaker.assert_called_once()
#
#                 # Second access should return cached factory
#                 factory2 = database_manager.session_factory
#                 assert factory2 == mock_factory
#                 assert mock_sessionmaker.call_count == 1
#
#     @pytest.mark.asyncio
#     async def test_database_manager_get_session(self, database_manager):
#         """Test get_session method."""
#         mock_session = AsyncMock(spec=AsyncSession)
#         mock_factory = MagicMock()
#         mock_factory.return_value = mock_session
#
#         with patch.object(database_manager, 'session_factory', mock_factory):
#             session = database_manager.get_session()
#
#             assert session == mock_session
#             mock_factory.assert_called_once()
#
#     @pytest.mark.asyncio
#     async def test_database_manager_close(self, database_manager):
#         """Test close method."""
#         mock_engine = AsyncMock()
#         database_manager._engine = mock_engine
#
#         await database_manager.close()
#
#         mock_engine.dispose.assert_called_once()
#         assert database_manager._engine is None
#         assert database_manager._session_factory is None
#
#     @pytest.mark.asyncio
#     async def test_database_manager_close_no_engine(self, database_manager):
#         """Test close method when no engine exists."""
#         # Should not raise an error
#         await database_manager.close()
#
#         assert database_manager._engine is None
#         assert database_manager._session_factory is None
#
#     @pytest.mark.asyncio
#     async def test_database_manager_health_check_success(self, database_manager):
#         """Test successful health check."""
#         mock_session = AsyncMock(spec=AsyncSession)
#         mock_result = MagicMock()
#         mock_result.scalar.return_value = 1
#         mock_session.execute.return_value = mock_result
#
#         with patch.object(database_manager, 'get_session', return_value=mock_session):
#             result = await database_manager.health_check()
#
#             assert result is True
#             mock_session.execute.assert_called_once()
#             mock_session.close.assert_called_once()
#
#     @pytest.mark.asyncio
#     async def test_database_manager_health_check_failure(self, database_manager):
#         """Test failed health check."""
#         mock_session = AsyncMock(spec=AsyncSession)
#         mock_session.execute.side_effect = SQLAlchemyError("Connection failed")
#
#         with patch.object(database_manager, 'get_session', return_value=mock_session):
#             result = await database_manager.health_check()
#
#             assert result is False
#             mock_session.close.assert_called_once()
#
#     @pytest.mark.asyncio
#     async def test_database_manager_context_manager(self, database_manager):
#         """Test DatabaseManager as async context manager."""
#         mock_engine = AsyncMock()
#         database_manager._engine = mock_engine
#
#         async with database_manager as manager:
#             assert manager == database_manager
#
#         mock_engine.dispose.assert_called_once()
#
#
# class TestCreateDatabaseEngine:
#     """Test create_database_engine function."""
#
#     def test_create_database_engine_default_settings(self):
#         """Test engine creation with default settings."""
#         database_url = "postgresql+asyncpg://test:test@localhost:5432/test_db"
#
#         with patch('app.config.database.create_async_engine') as mock_create:
#             mock_engine = MagicMock()
#             mock_create.return_value = mock_engine
#
#             engine = create_database_engine(database_url)
#
#             assert engine == mock_engine
#             mock_create.assert_called_once_with(
#                 database_url,
#                 echo=False,
#                 pool_size=5,
#                 max_overflow=10,
#                 pool_timeout=30,
#                 pool_recycle=3600,
#                 pool_pre_ping=True
#             )
#
#     def test_create_database_engine_custom_settings(self):
#         """Test engine creation with custom settings."""
#         database_url = "postgresql+asyncpg://test:test@localhost:5432/test_db"
#
#         with patch('app.config.database.create_async_engine') as mock_create:
#             mock_engine = MagicMock()
#             mock_create.return_value = mock_engine
#
#             engine = create_database_engine(
#                 database_url,
#                 echo=True,
#                 pool_size=10,
#                 max_overflow=20
#             )
#
#             assert engine == mock_engine
#             mock_create.assert_called_once_with(
#                 database_url,
#                 echo=True,
#                 pool_size=10,
#                 max_overflow=20,
#                 pool_timeout=30,
#                 pool_recycle=3600,
#                 pool_pre_ping=True
#             )
#
#     def test_create_database_engine_testing_mode(self):
#         """Test engine creation in testing mode."""
#         database_url = "sqlite+aiosqlite:///test.db"
#
#         with patch('app.config.database.create_async_engine') as mock_create:
#             mock_engine = MagicMock()
#             mock_create.return_value = mock_engine
#
#             engine = create_database_engine(database_url, is_testing=True)
#
#             assert engine == mock_engine
#             # Testing mode should have different pool settings
#             call_args = mock_create.call_args
#             assert call_args[1]['pool_size'] == 1
#             assert call_args[1]['max_overflow'] == 0
#
#
# class TestCheckDatabaseConnection:
#     """Test check_database_connection function."""
#
#     @pytest.mark.asyncio
#     async def test_check_database_connection_success(self):
#         """Test successful database connection check."""
#         mock_engine = AsyncMock(spec=AsyncEngine)
#         mock_connection = AsyncMock()
#         mock_result = MagicMock()
#         mock_result.scalar.return_value = 1
#         mock_connection.execute.return_value = mock_result
#         mock_engine.begin.return_value.__aenter__.return_value = mock_connection
#
#         result = await check_database_connection(mock_engine)
#
#         assert result is True
#         mock_engine.begin.assert_called_once()
#         mock_connection.execute.assert_called_once()
#
#     @pytest.mark.asyncio
#     async def test_check_database_connection_failure(self):
#         """Test failed database connection check."""
#         mock_engine = AsyncMock(spec=AsyncEngine)
#         mock_engine.begin.side_effect = OperationalError("Connection failed", None, None)
#
#         result = await check_database_connection(mock_engine)
#
#         assert result is False
#
#     @pytest.mark.asyncio
#     async def test_check_database_connection_timeout(self):
#         """Test database connection check with timeout."""
#         mock_engine = AsyncMock(spec=AsyncEngine)
#
#         # Mock a slow connection that times out
#         async def slow_begin():
#             await asyncio.sleep(2)  # Longer than timeout
#             return AsyncMock()
#
#         mock_engine.begin.side_effect = slow_begin
#
#         result = await check_database_connection(mock_engine, timeout=1)
#
#         assert result is False
#
#
# class TestInitDatabase:
#     """Test init_database function."""
#
#     @pytest.mark.asyncio
#     async def test_init_database_success(self):
#         """Test successful database initialization."""
#         mock_engine = AsyncMock(spec=AsyncEngine)
#
#         with patch('app.config.database.Base') as mock_base:
#             mock_metadata = MagicMock()
#             mock_base.metadata = mock_metadata
#
#             await init_database(mock_engine)
#
#             mock_metadata.create_all.assert_called_once_with(mock_engine)
#
#     @pytest.mark.asyncio
#     async def test_init_database_failure(self):
#         """Test database initialization failure."""
#         mock_engine = AsyncMock(spec=AsyncEngine)
#
#         with patch('app.config.database.Base') as mock_base:
#             mock_metadata = MagicMock()
#             mock_metadata.create_all.side_effect = SQLAlchemyError("Creation failed")
#             mock_base.metadata = mock_metadata
#
#             with pytest.raises(SQLAlchemyError):
#                 await init_database(mock_engine)
#
#
# class TestGetDatabaseManager:
#     """Test get_database_manager function."""
#
#     def test_get_database_manager_returns_instance(self):
#         """Test that get_database_manager returns DatabaseManager instance."""
#         with patch('app.config.database.get_settings') as mock_get_settings:
#             mock_settings = MagicMock(spec=Settings)
#             mock_get_settings.return_value = mock_settings
#
#             manager = get_database_manager()
#
#             assert isinstance(manager, DatabaseManager)
#             assert manager.settings == mock_settings
#
#     def test_get_database_manager_caching(self):
#         """Test that get_database_manager caches the instance."""
#         with patch('app.config.database.get_settings') as mock_get_settings:
#             mock_settings = MagicMock(spec=Settings)
#             mock_get_settings.return_value = mock_settings
#
#             # Clear cache first
#             get_database_manager.cache_clear()
#
#             manager1 = get_database_manager()
#             manager2 = get_database_manager()
#
#             # Should return the same instance due to caching
#             assert manager1 is manager2
#
#     def test_get_database_manager_cache_clear(self):
#         """Test that cache can be cleared."""
#         with patch('app.config.database.get_settings') as mock_get_settings:
#             mock_settings = MagicMock(spec=Settings)
#             mock_get_settings.return_value = mock_settings
#
#             manager1 = get_database_manager()
#             get_database_manager.cache_clear()
#             manager2 = get_database_manager()
#
#             # Should return different instances after cache clear
#             assert manager1 is not manager2
#
#
# class TestGetAsyncSession:
#     """Test get_async_session function."""
#
#     @pytest.mark.asyncio
#     async def test_get_async_session_returns_session(self):
#         """Test that get_async_session returns AsyncSession."""
#         mock_session = AsyncMock(spec=AsyncSession)
#         mock_manager = MagicMock()
#         mock_manager.get_session.return_value = mock_session
#
#         with patch('app.config.database.get_database_manager', return_value=mock_manager):
#             session = get_async_session()
#
#             assert session == mock_session
#             mock_manager.get_session.assert_called_once()
#
#     @pytest.mark.asyncio
#     async def test_get_async_session_dependency_injection(self):
#         """Test get_async_session as FastAPI dependency."""
#         mock_session = AsyncMock(spec=AsyncSession)
#         mock_manager = MagicMock()
#         mock_manager.get_session.return_value = mock_session
#
#         with patch('app.config.database.get_database_manager', return_value=mock_manager):
#             # Simulate FastAPI dependency injection
#             session_generator = get_async_session()
#             session = next(session_generator)
#
#             assert session == mock_session
#
#             # Test cleanup
#             try:
#                 next(session_generator)
#             except StopIteration:
#                 pass  # Expected behavior
#
#
# class TestDatabaseIntegration:
#     """Test database integration scenarios."""
#
#     @pytest.mark.asyncio
#     async def test_database_session_lifecycle(self):
#         """Test complete database session lifecycle."""
#         mock_settings = MagicMock(spec=Settings)
#         mock_settings.database_url = "postgresql+asyncpg://test:test@localhost:5432/test_db"
#         mock_settings.is_testing = False
#
#         manager = DatabaseManager(mock_settings)
#
#         with patch('app.config.database.create_async_engine') as mock_create_engine:
#             with patch('app.config.database.async_sessionmaker') as mock_sessionmaker:
#                 mock_engine = AsyncMock()
#                 mock_create_engine.return_value = mock_engine
#
#                 mock_session = AsyncMock(spec=AsyncSession)
#                 mock_factory = MagicMock()
#                 mock_factory.return_value = mock_session
#                 mock_sessionmaker.return_value = mock_factory
#
#                 # Get session
#                 session = manager.get_session()
#                 assert session == mock_session
#
#                 # Close manager
#                 await manager.close()
#                 mock_engine.dispose.assert_called_once()
#
#     @pytest.mark.asyncio
#     async def test_database_connection_retry(self):
#         """Test database connection retry logic."""
#         mock_engine = AsyncMock(spec=AsyncEngine)
#
#         # First attempt fails, second succeeds
#         mock_connection = AsyncMock()
#         mock_result = MagicMock()
#         mock_result.scalar.return_value = 1
#         mock_connection.execute.return_value = mock_result
#
#         mock_engine.begin.side_effect = [
#             OperationalError("Connection failed", None, None),
#             AsyncMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_connection)))
#         ]
#
#         # This would require implementing retry logic in the actual function
#         # For now, we test that the first attempt fails
#         result = await check_database_connection(mock_engine)
#         assert result is False
#
#     @pytest.mark.asyncio
#     async def test_database_transaction_handling(self):
#         """Test database transaction handling."""
#         mock_session = AsyncMock(spec=AsyncSession)
#         mock_manager = MagicMock()
#         mock_manager.get_session.return_value = mock_session
#
#         with patch('app.config.database.get_database_manager', return_value=mock_manager):
#             session = get_async_session()
#
#             # Simulate transaction operations
#             await session.begin()
#             await session.commit()
#             await session.close()
#
#             mock_session.begin.assert_called_once()
#             mock_session.commit.assert_called_once()
#             mock_session.close.assert_called_once()
#
#     @pytest.mark.asyncio
#     async def test_database_error_handling(self):
#         """Test database error handling scenarios."""
#         mock_session = AsyncMock(spec=AsyncSession)
#         mock_session.execute.side_effect = SQLAlchemyError("Database error")
#
#         mock_manager = MagicMock()
#         mock_manager.get_session.return_value = mock_session
#
#         with patch('app.config.database.get_database_manager', return_value=mock_manager):
#             session = get_async_session()
#
#             # Should handle database errors gracefully
#             with pytest.raises(SQLAlchemyError):
#                 await session.execute(text("SELECT 1"))
#
#             # Session should still be closed properly
#             await session.close()
#             mock_session.close.assert_called_once()
#
#
# class TestDatabaseConfiguration:
#     """Test database configuration scenarios."""
#
#     def test_database_url_parsing(self):
#         """Test database URL parsing for different databases."""
#         test_urls = [
#             "postgresql+asyncpg://user:pass@localhost:5432/dbname",
#             "sqlite+aiosqlite:///./test.db",
#             "mysql+aiomysql://user:pass@localhost:3306/dbname",
#         ]
#
#         for url in test_urls:
#             with patch('app.config.database.create_async_engine') as mock_create:
#                 mock_engine = MagicMock()
#                 mock_create.return_value = mock_engine
#
#                 engine = create_database_engine(url)
#
#                 assert engine == mock_engine
#                 mock_create.assert_called_once()
#                 assert mock_create.call_args[0][0] == url
#
#     def test_database_pool_configuration(self):
#         """Test database connection pool configuration."""
#         database_url = "postgresql+asyncpg://test:test@localhost:5432/test_db"
#
#         with patch('app.config.database.create_async_engine') as mock_create:
#             mock_engine = MagicMock()
#             mock_create.return_value = mock_engine
#
#             # Test production configuration
#             create_database_engine(database_url, is_testing=False)
#
#             call_args = mock_create.call_args[1]
#             assert call_args['pool_size'] == 5
#             assert call_args['max_overflow'] == 10
#             assert call_args['pool_timeout'] == 30
#             assert call_args['pool_recycle'] == 3600
#             assert call_args['pool_pre_ping'] is True
#
#     def test_database_testing_configuration(self):
#         """Test database configuration for testing."""
#         database_url = "sqlite+aiosqlite:///test.db"
#
#         with patch('app.config.database.create_async_engine') as mock_create:
#             mock_engine = MagicMock()
#             mock_create.return_value = mock_engine
#
#             # Test testing configuration
#             create_database_engine(database_url, is_testing=True)
#
#             call_args = mock_create.call_args[1]
#             assert call_args['pool_size'] == 1
#             assert call_args['max_overflow'] == 0
#
#     def test_database_debug_configuration(self):
#         """Test database configuration with debug mode."""
#         database_url = "postgresql+asyncpg://test:test@localhost:5432/test_db"
#
#         with patch('app.config.database.create_async_engine') as mock_create:
#             mock_engine = MagicMock()
#             mock_create.return_value = mock_engine
#
#             # Test debug configuration
#             create_database_engine(database_url, echo=True)
#
#             call_args = mock_create.call_args[1]
#             assert call_args['echo'] is True