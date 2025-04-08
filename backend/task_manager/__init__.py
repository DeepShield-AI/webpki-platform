
'''
    Manager base class
'''
from abc import ABC, abstractmethod
from .task import Task
from ..logger.logger import primary_logger

class Manager(ABC):

    def __init__(self) -> None:
        super().__init__()

    @abstractmethod
    def register_task(self, task : Task):
        pass

    @abstractmethod
    def start_task(self, task_id : int):
        pass

    @abstractmethod
    def pause_task(self, task_id : int):
        pass

    @abstractmethod
    def resume_task(self, task_id : int):
        pass

    @abstractmethod
    def kill_task(self, task_id : int):
        pass

# Global thread pool, covers all the tasks thread allocation
from concurrent.futures import ProcessPoolExecutor
GLOBAL_MAX_PROCESSES = 20
g_process_executor = ProcessPoolExecutor(max_workers=GLOBAL_MAX_PROCESSES)

# Global thread pool, covers all the tasks thread allocation
from concurrent.futures import ThreadPoolExecutor
GLOBAL_MAX_THREADS = 1000
g_thread_executor = ThreadPoolExecutor(max_workers=GLOBAL_MAX_THREADS)
# g_thread_executor.submit(idie)
'''
    Keep in mind that this is not the main thread!!!
    Main thread only is __name__ == __main__ !!!
    In the previous code, the main thread terminates after
        g_manager.start_submitted_tasks()
    So, if you press ctrl+C somewhere in this global thread or something, this definately
    not gonna stops....

    So, now I want to change this g_thread_executor to a thread list that stores the start task threads
    generated from the main thread
'''

'''
    The overall structure of the thread_pool is:

        g_thread_executor
                    | - start_task() - start()
                                            | - executor - ...
                                            | - executor - ...
                    | - start_task() - start()
                                            | - executor - ...
                                            | - executor - ...
                    | - start_task() - start()
                                            | - executor - ...
                                            | - executor - ...
    So, when shutting down, we need to stop the thread correspondingly
    ...
'''

'''
    The thing is: we cannot call ThreadPoolExecutor.submit in any child thread
    nor ProcessPoolExecutor.submit not in main process
    (though I have no idea why, but it cannot)
    TODO: There are two ways:
    1. Delete the thread/process for manager task_scheduler and run start_submitted_task manually
    This will ensure that the start_task function runs in the main process
    2. Need to think a way to implement ProcessPool and ThreadPool by myself
    This can skip the constraints implemented in concurrent library
'''

# global task manager
import multiprocessing
from .task_manager import GlobalTaskManager
g_manager = GlobalTaskManager()
# self.task_scheduler_thread = Thread(target=self.task_scheduler, args=())
# self.task_scheduler_thread.start()
# multiprocessing.freeze_support()
# p = multiprocessing.Process(target=g_manager.task_scheduler)
# p.start()

# 定义全局的退出事件
# Right now, we add Crtl+C signal processing here
# 子线程 - 子线程池 - 根线程 - 根线程池 - 静态资源
import sys
import signal

def signal_handler(sig, frame):
    primary_logger.warning("Ctrl+C detected")
    g_manager.ctrl_c_handler()
    g_thread_executor.shutdown(wait=True)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
primary_logger.info("Crtl+C signal handler attached!")
