"""Performance and load tests for the authentication system."""

import pytest
import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch, AsyncMock
import statistics

from httpx import AsyncClient
from app.models.user import User
from app.core.jwt import jwt_service
from app.core.password import hash_password


@pytest.mark.performance
class TestAuthenticationPerformance:
    """Performance tests for authentication endpoints."""

    @pytest.mark.asyncio
    async def test_login_performance_single_user(self, async_client: AsyncClient, test_user: User):
        """Test login performance for a single user."""
        login_times = []
        
        for _ in range(100):
            start_time = time.perf_counter()
            
            response = await async_client.post(
                "/api/v1/auth/token",
                data={
                    "username": test_user.username,
                    "password": "TestPassword123!"
                }
            )
            
            end_time = time.perf_counter()
            login_times.append(end_time - start_time)
            
            assert response.status_code == 200
        
        # Performance assertions
        avg_time = statistics.mean(login_times)
        max_time = max(login_times)
        p95_time = statistics.quantiles(login_times, n=20)[18]  # 95th percentile
        
        assert avg_time < 0.5, f"Average login time {avg_time:.3f}s exceeds 500ms"
        assert max_time < 2.0, f"Maximum login time {max_time:.3f}s exceeds 2s"
        assert p95_time < 1.0, f"95th percentile login time {p95_time:.3f}s exceeds 1s"

    @pytest.mark.asyncio
    async def test_concurrent_login_performance(self, async_client: AsyncClient, test_users: list[User]):
        """Test concurrent login performance."""
        async def login_user(user: User):
            start_time = time.perf_counter()
            
            response = await async_client.post(
                "/api/v1/auth/token",
                data={
                    "username": user.username,
                    "password": "TestPassword123!"
                }
            )
            
            end_time = time.perf_counter()
            return end_time - start_time, response.status_code
        
        # Create tasks for concurrent logins (reduce to 20 for Docker environment)
        tasks = [login_user(user) for user in test_users[:20]]  # Test with 20 concurrent users
        
        start_time = time.perf_counter()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        total_time = time.perf_counter() - start_time
        
        # Filter out exceptions and analyze results
        successful_results = [r for r in results if not isinstance(r, Exception)]
        failed_results = [r for r in results if isinstance(r, Exception)]
        
        if failed_results:
            print(f"Failed requests: {len(failed_results)}")
            for i, exc in enumerate(failed_results[:3]):  # Show first 3 exceptions
                print(f"Exception {i+1}: {exc}")
        
        # Analyze successful results
        if successful_results:
            login_times = [result[0] for result in successful_results]
            status_codes = [result[1] for result in successful_results]
            
            # At least 80% of requests should succeed
            success_rate = len(successful_results) / len(results)
            assert success_rate >= 0.8, f"Success rate {success_rate:.2%} is below 80%"
            
            # All successful requests should have status 200
            failed_status_codes = [code for code in status_codes if code != 200]
            if failed_status_codes:
                print(f"Non-200 status codes: {failed_status_codes}")
            assert all(code == 200 for code in status_codes), f"Some successful requests had non-200 status codes: {failed_status_codes}"
        else:
            pytest.fail("All concurrent login requests failed")
        
            # Performance assertions
            avg_time = statistics.mean(login_times)
            throughput = len(successful_results) / total_time
            
            assert avg_time < 1.0, f"Average concurrent login time {avg_time:.3f}s exceeds 1s"
            assert throughput > 10, f"Throughput {throughput:.1f} req/s is below 10 req/s"

    @pytest.mark.asyncio
    async def test_token_validation_performance(self, test_access_token: str):
        """Test JWT token validation performance."""
        validation_times = []
        
        for _ in range(1000):
            start_time = time.perf_counter()
            
            payload = jwt_service.validate_token(test_access_token)
            
            end_time = time.perf_counter()
            validation_times.append(end_time - start_time)
            
            assert payload is not None
        
        # Performance assertions
        avg_time = statistics.mean(validation_times)
        max_time = max(validation_times)
        
        assert avg_time < 0.01, f"Average token validation time {avg_time:.6f}s exceeds 10ms"
        assert max_time < 0.1, f"Maximum token validation time {max_time:.6f}s exceeds 100ms"

    @pytest.mark.asyncio
    async def test_password_hashing_performance(self):
        """Test password hashing performance."""
        passwords = [f"TestPassword{i}!" for i in range(100)]
        hashing_times = []
        
        for password in passwords:
            start_time = time.perf_counter()
            
            password_hash = hash_password(password)
            
            end_time = time.perf_counter()
            hashing_times.append(end_time - start_time)
            
            assert password_hash is not None
            assert len(password_hash) > 50  # Argon2 hash should be substantial
        
        # Performance assertions
        avg_time = statistics.mean(hashing_times)
        max_time = max(hashing_times)
        
        # Password hashing should be intentionally slow for security
        assert 0.1 < avg_time < 1.0, f"Average hashing time {avg_time:.3f}s outside expected range"
        assert max_time < 2.0, f"Maximum hashing time {max_time:.3f}s exceeds 2s"

    @pytest.mark.asyncio
    async def test_refresh_token_performance(self, async_client: AsyncClient, test_user: User):
        """Test refresh token performance."""
        # First, get a refresh token
        login_response = await async_client.post(
            "/api/v1/auth/token",
            data={
                "username": test_user.username,
                "password": "TestPassword123!"
            }
        )
        
        refresh_token = login_response.json()["refresh_token"]
        refresh_times = []
        
        for _ in range(50):
            start_time = time.perf_counter()
            
            response = await async_client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": refresh_token}
            )
            
            end_time = time.perf_counter()
            refresh_times.append(end_time - start_time)
            
            assert response.status_code == 200
            # Update refresh token for next iteration
            refresh_token = response.json()["refresh_token"]
        
        # Performance assertions
        avg_time = statistics.mean(refresh_times)
        max_time = max(refresh_times)
        
        assert avg_time < 0.5, f"Average refresh time {avg_time:.3f}s exceeds 500ms"
        assert max_time < 2.0, f"Maximum refresh time {max_time:.3f}s exceeds 2s"


@pytest.mark.performance
class TestDatabasePerformance:
    """Performance tests for database operations."""

    @pytest.mark.asyncio
    async def test_user_query_performance(self, db_session, test_users: list[User]):
        """Test user query performance."""
        from sqlalchemy import select
        
        query_times = []
        
        for _ in range(100):
            start_time = time.perf_counter()
            
            # Query users
            result = await db_session.execute(
                select(User).where(User.is_active == True).limit(10)
            )
            users = result.scalars().all()
            
            end_time = time.perf_counter()
            query_times.append(end_time - start_time)
            
            assert len(users) > 0
        
        # Performance assertions
        avg_time = statistics.mean(query_times)
        max_time = max(query_times)
        
        assert avg_time < 0.01, f"Average query time {avg_time:.6f}s exceeds 10ms"
        assert max_time < 0.05, f"Maximum query time {max_time:.6f}s exceeds 50ms"

    @pytest.mark.asyncio
    async def test_user_creation_performance(self, db_session):
        """Test user creation performance."""
        creation_times = []
        
        for i in range(50):
            start_time = time.perf_counter()
            
            # Create user
            user = User(
                username=f"perf_user_{i}",
                email=f"perf_user_{i}@example.com",
                password_hash=hash_password("PerfPassword123!")
            )
            
            db_session.add(user)
            await db_session.commit()
            await db_session.refresh(user)
            
            end_time = time.perf_counter()
            creation_times.append(end_time - start_time)
            
            assert user.id is not None
        
        # Performance assertions
        avg_time = statistics.mean(creation_times)
        max_time = max(creation_times)
        
        assert avg_time < 0.1, f"Average creation time {avg_time:.3f}s exceeds 100ms"
        assert max_time < 0.5, f"Maximum creation time {max_time:.3f}s exceeds 500ms"

    @pytest.mark.asyncio
    async def test_concurrent_database_operations(self, db_session):
        """Test concurrent database operations."""
        async def create_and_query_user(index: int):
            start_time = time.perf_counter()
            
            # Create user
            user = User(
                username=f"concurrent_user_{index}",
                email=f"concurrent_user_{index}@example.com",
                password_hash=hash_password("ConcurrentPassword123!")
            )
            
            db_session.add(user)
            await db_session.commit()
            await db_session.refresh(user)
            
            # Query user
            from sqlalchemy import select
            result = await db_session.execute(
                select(User).where(User.id == user.id)
            )
            queried_user = result.scalar_one()
            
            end_time = time.perf_counter()
            return end_time - start_time, queried_user is not None
        
        # Create tasks for concurrent operations
        tasks = [create_and_query_user(i) for i in range(20)]
        
        start_time = time.perf_counter()
        results = await asyncio.gather(*tasks)
        total_time = time.perf_counter() - start_time
        
        # Analyze results
        operation_times = [result[0] for result in results]
        success_flags = [result[1] for result in results]
        
        # All operations should succeed
        assert all(success_flags), "Some database operations failed"
        
        # Performance assertions
        avg_time = statistics.mean(operation_times)
        throughput = len(tasks) / total_time
        
        assert avg_time < 0.2, f"Average operation time {avg_time:.3f}s exceeds 200ms"
        assert throughput > 50, f"Throughput {throughput:.1f} ops/s is below 50 ops/s"


@pytest.mark.performance
class TestRedisPerformance:
    """Performance tests for Redis operations."""

    @pytest.mark.asyncio
    async def test_redis_get_set_performance(self, redis_client):
        """Test Redis GET/SET performance."""
        set_times = []
        get_times = []
        
        # Test SET operations
        for i in range(1000):
            start_time = time.perf_counter()
            
            await redis_client.set(f"perf_key_{i}", f"perf_value_{i}")
            
            end_time = time.perf_counter()
            set_times.append(end_time - start_time)
        
        # Test GET operations
        for i in range(1000):
            start_time = time.perf_counter()
            
            value = await redis_client.get(f"perf_key_{i}")
            
            end_time = time.perf_counter()
            get_times.append(end_time - start_time)
            
            assert value == f"perf_value_{i}"
        
        # Performance assertions
        avg_set_time = statistics.mean(set_times)
        avg_get_time = statistics.mean(get_times)
        
        assert avg_set_time < 0.001, f"Average SET time {avg_set_time:.6f}s exceeds 1ms"
        assert avg_get_time < 0.001, f"Average GET time {avg_get_time:.6f}s exceeds 1ms"

    @pytest.mark.asyncio
    async def test_redis_pipeline_performance(self, redis_client):
        """Test Redis pipeline performance."""
        # Test individual operations
        individual_times = []
        for i in range(100):
            start_time = time.perf_counter()
            
            await redis_client.set(f"individual_{i}", f"value_{i}")
            await redis_client.get(f"individual_{i}")
            
            end_time = time.perf_counter()
            individual_times.append(end_time - start_time)
        
        # Test pipeline operations
        start_time = time.perf_counter()
        
        pipe = redis_client.pipeline()
        for i in range(100):
            pipe.set(f"pipeline_{i}", f"value_{i}")
            pipe.get(f"pipeline_{i}")
        
        results = await pipe.execute()
        
        pipeline_time = time.perf_counter() - start_time
        
        # Performance comparison
        total_individual_time = sum(individual_times)
        
        assert pipeline_time < total_individual_time / 2, \
            f"Pipeline time {pipeline_time:.3f}s not significantly faster than individual operations"
        
        # Verify results
        assert len(results) == 200  # 100 SET + 100 GET operations

    @pytest.mark.asyncio
    async def test_concurrent_redis_operations(self, redis_client):
        """Test concurrent Redis operations."""
        async def redis_operations(index: int):
            start_time = time.perf_counter()
            
            # Multiple operations per task
            await redis_client.set(f"concurrent_{index}", f"value_{index}")
            value = await redis_client.get(f"concurrent_{index}")
            await redis_client.delete(f"concurrent_{index}")
            
            end_time = time.perf_counter()
            return end_time - start_time, value == f"value_{index}"
        
        # Create tasks for concurrent operations
        tasks = [redis_operations(i) for i in range(100)]
        
        start_time = time.perf_counter()
        results = await asyncio.gather(*tasks)
        total_time = time.perf_counter() - start_time
        
        # Analyze results
        operation_times = [result[0] for result in results]
        success_flags = [result[1] for result in results]
        
        # All operations should succeed
        assert all(success_flags), "Some Redis operations failed"
        
        # Performance assertions
        avg_time = statistics.mean(operation_times)
        throughput = len(tasks) / total_time
        
        assert avg_time < 0.01, f"Average operation time {avg_time:.6f}s exceeds 10ms"
        assert throughput > 1000, f"Throughput {throughput:.1f} ops/s is below 1000 ops/s"


@pytest.mark.performance
class TestAPIEndpointPerformance:
    """Performance tests for API endpoints."""

    @pytest.mark.asyncio
    async def test_user_list_performance(self, async_client: AsyncClient, admin_access_token: str, test_users: list[User]):
        """Test user list endpoint performance."""
        request_times = []
        
        for _ in range(50):
            start_time = time.perf_counter()
            
            response = await async_client.get(
                "/api/v1/users",
                headers={"Authorization": f"Bearer {admin_access_token}"}
            )
            
            end_time = time.perf_counter()
            request_times.append(end_time - start_time)
            
            assert response.status_code == 200
            users_data = response.json()
            assert "users" in users_data
        
        # Performance assertions
        avg_time = statistics.mean(request_times)
        max_time = max(request_times)
        
        assert avg_time < 0.1, f"Average request time {avg_time:.3f}s exceeds 100ms"
        assert max_time < 0.5, f"Maximum request time {max_time:.3f}s exceeds 500ms"

    @pytest.mark.asyncio
    async def test_user_creation_endpoint_performance(self, async_client: AsyncClient, admin_access_token: str):
        """Test user creation endpoint performance."""
        creation_times = []
        
        for i in range(20):
            user_data = {
                "username": f"api_perf_user_{i}",
                "email": f"api_perf_user_{i}@example.com",
                "password": "ApiPerfPassword123!"
            }
            
            start_time = time.perf_counter()
            
            response = await async_client.post(
                "/api/v1/users",
                headers={"Authorization": f"Bearer {admin_access_token}"},
                json=user_data
            )
            
            end_time = time.perf_counter()
            creation_times.append(end_time - start_time)
            
            assert response.status_code == 201
        
        # Performance assertions
        avg_time = statistics.mean(creation_times)
        max_time = max(creation_times)
        
        assert avg_time < 0.2, f"Average creation time {avg_time:.3f}s exceeds 200ms"
        assert max_time < 1.0, f"Maximum creation time {max_time:.3f}s exceeds 1s"

    @pytest.mark.asyncio
    async def test_concurrent_api_requests(self, async_client: AsyncClient, user_access_token: str):
        """Test concurrent API requests."""
        async def make_request():
            start_time = time.perf_counter()
            
            response = await async_client.get(
                "/api/v1/users/me",
                headers={"Authorization": f"Bearer {user_access_token}"}
            )
            
            end_time = time.perf_counter()
            return end_time - start_time, response.status_code
        
        # Create tasks for concurrent requests
        tasks = [make_request() for _ in range(100)]
        
        start_time = time.perf_counter()
        results = await asyncio.gather(*tasks)
        total_time = time.perf_counter() - start_time
        
        # Analyze results
        request_times = [result[0] for result in results]
        status_codes = [result[1] for result in results]
        
        # All requests should succeed
        assert all(code == 200 for code in status_codes), "Some API requests failed"
        
        # Performance assertions
        avg_time = statistics.mean(request_times)
        throughput = len(tasks) / total_time
        
        assert avg_time < 0.1, f"Average request time {avg_time:.3f}s exceeds 100ms"
        assert throughput > 200, f"Throughput {throughput:.1f} req/s is below 200 req/s"


@pytest.mark.performance
class TestMemoryPerformance:
    """Memory usage performance tests."""

    @pytest.mark.asyncio
    async def test_memory_usage_during_load(self, async_client: AsyncClient, test_user: User):
        """Test memory usage during high load."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Perform many operations
        tasks = []
        for _ in range(200):
            task = async_client.post(
                "/api/v1/auth/token",
                data={
                    "username": test_user.username,
                    "password": "TestPassword123!"
                }
            )
            tasks.append(task)
        
        responses = await asyncio.gather(*tasks)
        
        # Check memory after operations
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # All requests should succeed
        assert all(r.status_code == 200 for r in responses)
        
        # Memory increase should be reasonable
        assert memory_increase < 100, f"Memory increased by {memory_increase:.1f}MB, which is excessive"

    @pytest.mark.asyncio
    async def test_token_cache_memory_efficiency(self):
        """Test memory efficiency of token caching."""
        import sys
        
        # Create many tokens
        tokens = []
        for i in range(1000):
            payload = {
                "sub": f"user_{i}",
                "username": f"user_{i}",
                "scopes": ["read", "write"]
            }
            token = jwt_service.create_access_token(payload)
            tokens.append(token)
        
        # Measure memory usage of tokens
        token_memory = sum(sys.getsizeof(token) for token in tokens)
        avg_token_size = token_memory / len(tokens)
        
        # Tokens should be reasonably sized
        assert avg_token_size < 1000, f"Average token size {avg_token_size:.1f} bytes is too large"
        assert token_memory < 1024 * 1024, f"Total token memory {token_memory} bytes exceeds 1MB"


@pytest.mark.performance
class TestScalabilityTests:
    """Scalability and stress tests."""

    @pytest.mark.asyncio
    async def test_user_scalability(self, db_session):
        """Test system behavior with many users."""
        # Create many users efficiently
        users = []
        for i in range(1000):
            user = User(
                username=f"scale_user_{i}",
                email=f"scale_user_{i}@example.com",
                password_hash=hash_password("ScalePassword123!")
            )
            users.append(user)
        
        start_time = time.perf_counter()
        
        # Batch insert users
        db_session.add_all(users)
        await db_session.commit()
        
        creation_time = time.perf_counter() - start_time
        
        # Query performance with many users
        from sqlalchemy import select, func
        
        start_time = time.perf_counter()
        
        result = await db_session.execute(
            select(func.count(User.id)).where(User.is_active == True)
        )
        user_count = result.scalar()
        
        query_time = time.perf_counter() - start_time
        
        # Performance assertions
        assert creation_time < 10.0, f"Creating 1000 users took {creation_time:.3f}s, exceeds 10s"
        assert query_time < 0.1, f"Counting users took {query_time:.6f}s, exceeds 100ms"
        assert user_count >= 1000, f"Expected at least 1000 users, got {user_count}"

    @pytest.mark.asyncio
    async def test_session_scalability(self, redis_client):
        """Test session storage scalability."""
        import json
        
        # Create many sessions
        sessions = {}
        for i in range(10000):
            session_id = f"session_{i}"
            session_data = {
                "user_id": f"user_{i}",
                "username": f"user_{i}",
                "login_time": "2023-01-01T10:00:00Z",
                "permissions": ["read", "write"]
            }
            sessions[session_id] = session_data
        
        # Store sessions
        start_time = time.perf_counter()
        
        pipe = redis_client.pipeline()
        for session_id, session_data in sessions.items():
            pipe.set(f"session:{session_id}", json.dumps(session_data), ex=3600)
        
        await pipe.execute()
        
        storage_time = time.perf_counter() - start_time
        
        # Retrieve sessions
        start_time = time.perf_counter()
        
        pipe = redis_client.pipeline()
        for session_id in list(sessions.keys())[:100]:  # Sample 100 sessions
            pipe.get(f"session:{session_id}")
        
        results = await pipe.execute()
        
        retrieval_time = time.perf_counter() - start_time
        
        # Performance assertions
        assert storage_time < 5.0, f"Storing 10k sessions took {storage_time:.3f}s, exceeds 5s"
        assert retrieval_time < 0.1, f"Retrieving 100 sessions took {retrieval_time:.6f}s, exceeds 100ms"
        assert all(result is not None for result in results), "Some sessions were not stored properly"

    @pytest.mark.asyncio
    async def test_rate_limiting_scalability(self, redis_client):
        """Test rate limiting with many users."""
        # Simulate rate limiting for many users
        user_count = 1000
        requests_per_user = 10
        
        start_time = time.perf_counter()
        
        # Use pipeline for efficiency
        pipe = redis_client.pipeline()
        
        for user_id in range(user_count):
            for request_num in range(requests_per_user):
                rate_limit_key = f"rate_limit:user_{user_id}"
                pipe.incr(rate_limit_key)
                if request_num == 0:  # Set expiration on first request
                    pipe.expire(rate_limit_key, 60)
        
        results = await pipe.execute()
        
        processing_time = time.perf_counter() - start_time
        
        # Performance assertions
        expected_operations = user_count * requests_per_user * 2  # INCR + EXPIRE for first request
        actual_operations = len(results)
        
        assert processing_time < 2.0, f"Processing {actual_operations} operations took {processing_time:.3f}s, exceeds 2s"
        
        # Verify rate limiting worked
        throughput = actual_operations / processing_time
        assert throughput > 5000, f"Throughput {throughput:.1f} ops/s is below 5000 ops/s"