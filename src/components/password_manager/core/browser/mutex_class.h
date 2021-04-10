#include <iostream>       // std::cout
#include <mutex>          // std::mutex

class MutexClass{

   public:
   
   static std::mutex mtx;           // mutex for critical section

};

