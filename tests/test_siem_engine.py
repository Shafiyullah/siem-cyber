import pytest
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
from siem_engine import SIEMEngine

@pytest.mark.asyncio
async def test_initialize():
    with patch('siem_engine.ElasticsearchStorage') as MockStorage, \
         patch('siem_engine.LogCollector') as MockCollector:
        
        # Setup async mocks for storage
        mock_storage_instance = MockStorage.return_value
        mock_storage_instance.initialize = AsyncMock()
        mock_storage_instance.search_logs = AsyncMock(return_value=[]) # Return empty list for historical logs
        
        engine = SIEMEngine()
        await engine.initialize(['test.log'])
        
        assert engine.collector is not None
        assert engine.storage is not None
        mock_storage_instance.initialize.assert_awaited_once()

@pytest.mark.asyncio
async def test_start_stop_monitoring():
    with patch('siem_engine.ElasticsearchStorage') as MockStorage, \
         patch('siem_engine.LogCollector') as MockCollector:
        
        mock_storage_instance = MockStorage.return_value
        mock_storage_instance.initialize = AsyncMock()
        mock_storage_instance.search_logs = AsyncMock(return_value=[])
        mock_storage_instance.store_bulk_logs = AsyncMock()
        
        # Setup mock collector to return an async iterator
        mock_collector_instance = MockCollector.return_value
        mock_collector_instance.log_sources = ['test.log']
        
        async def async_gen(source):
            yield {"message": "test log"}
            await asyncio.sleep(0.1) # Simulate work
            
        mock_collector_instance.collect_from_file.side_effect = async_gen

        engine = SIEMEngine()
        await engine.initialize(['test.log'])
        
        # Start monitoring
        task = asyncio.create_task(engine.start_monitoring())
        await asyncio.sleep(0.1) # Let it start
        
        assert engine.is_running
        assert len(engine.monitoring_tasks) == 1
        
        # Stop monitoring
        await engine.stop_monitoring()
        
        assert not engine.is_running
        assert len(engine.monitoring_tasks) == 0
        
        await task

@pytest.mark.asyncio
async def test_reconfiguration():
    with patch('siem_engine.ElasticsearchStorage') as MockStorage, \
         patch('siem_engine.LogCollector') as MockCollector:
         
        mock_storage_instance = MockStorage.return_value
        mock_storage_instance.initialize = AsyncMock()
        mock_storage_instance.search_logs = AsyncMock(return_value=[])
        mock_storage_instance.store_bulk_logs = AsyncMock()

        mock_collector_instance = MockCollector.return_value
        mock_collector_instance.log_sources = ['test.log']
        mock_collector_instance.collect_from_file.return_value = AsyncMock() # Dummy

        engine = SIEMEngine()
        await engine.initialize(['test.log'])
        
        # Start
        asyncio.create_task(engine.start_monitoring())
        await asyncio.sleep(0.01)
        assert engine.is_running
        
        # Reconfigure (simulate API call)
        await engine.stop_monitoring()
        await engine.initialize(['new.log'])
        asyncio.create_task(engine.start_monitoring())
        
        await asyncio.sleep(0.01)
        assert engine.is_running
        await engine.stop_monitoring()
