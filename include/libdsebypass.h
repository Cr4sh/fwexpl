
typedef void (* KERNEL_EXPL_HANDLER)(void *context);

extern "C"
{

bool kernel_expl_load_driver(void *data, unsigned int data_size);

}
