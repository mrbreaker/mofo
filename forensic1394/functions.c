#include "ruby.h"
#include "forensic1394.h"
#include "common.h"

static VALUE f_init(VALUE self)
{
  VALUE arr;


  arr = rb_ary_new();
  rb_iv_set(self, "@arr", arr);
  return self;
}


static forensic1394_bus* getBus(VALUE bus){
	forensic1394_bus* r;
	Data_Get_Struct(bus,forensic1394_bus,r);	
	return r;
}
//THIS IS THE AUTOMATIC DESTRUCTOR ? NOTE THIS IS NOT A DIRECT WRAP
static void c_forensic1394_destroy(forensic1394_bus *bus){
	forensic1394_destroy(bus);
	free(bus);
}

static forensic1394_dev* getDev(VALUE dev){
	forensic1394_dev* r;
	Data_Get_Struct(dev,forensic1394_dev,r);	
	return r;
}

static forensic1394_req* getReq(VALUE req){
	forensic1394_req* r;
	Data_Get_Struct(req,forensic1394_req,r);	
	return r;
}

//TODO: Wrap the forensic1394_req structure
// C def: struct { uint64_t addr, size_t len, void *buf }
VALUE c_forensic1394_req;

// C def: forensic1394_bus *forensic1394_alloc(void)
static VALUE c_forensic1394_alloc(VALUE self){
	refturn Qnil; 
}

//g C def: forensic1394_result forensic1394_enable_sbp2(forensic1394_bus *bus)
//TODO:check function ordering
static VALUE c_forensic1394_enable_sbp2(VALUE self,VALUE rb_bus){
	return INT2FIX(forensic1394_enable_sbp2( getBus(rb_bus) ));
}

//g C def: forensic1394_dev **forensic1394_get_devices(forensic1394_bus *bus,
//g                                                    int *ndev,
//g   
//                                                 forensic1394_device_callback ondestroy)
static VALUE c_forensic1394_get_devices(VALUE bus,VALUE ndev,VALUE ondestroy){
	//TODO: write this
	//rb_dev = Data_Make_Struct(rb_bus,forensic1394_bus,NULL,c_forensic1394_destroy,bus);
}

//g C def: void forensic1394_close_device(forensic1394_dev *dev)
static void c_forensic1394_close_device(forensic1394_dev *dev){
	forensic1394_close_devic(dev);
	free(dev);
}


//g C def: forensic1394_result forensic1394_open_device(forensic1394_dev *dev)
static VALUE c_forensic1394_open_device(VALUE dev){
	forensic1394_open_device(getDev(dev));
	return Qnil;
}

//g C def: int forensic1394_device_is_open(forensic1394_dev *dev)
static VALUE c_forensic1394_device_is_open(VALUE dev){
	//TODO: unwrap
	return INT2FIX( forensic1394_device_is_open(dev) );
}

//g C def: forensic1394_result forensic1394_read_device(forensic1394_dev *dev,
//g                                                     uint64_t addr,
//g                                                     size_t len, void *buf)
static VALUE c_forensic1394_read_device(VALUE dev,VALUE addr,VALUE len,VALUE rb_buf){
	//unwrap dev
	char* buf = malloc(1024);//SRSLY TODO: change buf
	return INT2FIX( forensic1394_read_device(getDev(dev),NUM2LONG(addr),NUM2LONG(len),buf) );
	//TODO: write this
}

//g C def: forensic1394_result forensic1394_read_device_v(forensic1394_dev *dev,
//g                                                       forensic1394_req *req,
//g                                                       size_t nreq)
static VALUE c_forensic1394_read_device_v(VALUE dev,VALUE req,VALUE nreq){
	return INT2FIX(forensic1394_read_device_v(getDev(dev),getReq(req),NUM2LONG(nreq)) );
}

//g C def: forensic1394_result forensic1394_write_device(forensic1394_dev *dev,
//g                                                      uint64_t addr,
//g                                                      size_t len, void *buf)
static VALUE c_forensic1394_write_device(VALUE dev,VALUE addr,VALUE len,VALUE rb_buf){
	char *buf;//TODO: write this
	return INT2FIX(forensic1394_write_device(getDev(dev),NUM2LONG(addr),NUM2LONG(len),buf));
}

//g C def: forensic1394_result forensic1394_write_device_v(forensic1394_dev *dev,
//g                                                        forensic1394_req *req,
//g                                                        size_t nreq)
static VALUE c_forensic1394_write_device_v(VALUE dev,VALUE req,VALUE nreq){
	return INT2FIX(forensic1394_write_device_v(getDev(dev),getReq(req),NUM2LONG(nreq)));
}

//g C def: void forensic1394_get_device_csr(forensic1394_dev *dev, uint32_t *rom)
static VALUE c_forensic1394_get_device_csr(VALUE dev, VALUE rom){
	//TODO: write this
	forensic1394_get_device_csr(getDev(dev),rom);
	return Qnil;
}

//g C def: uint16_t forensic1394_get_device_node_id(forensic1394_dev *dev)
static VALUE c_forensic1394_get_device_node_id(VALUE dev){
	//TODO: write this
	return INT2FIX( forensic1394_get_device_node_id(dev));
}

//g C def: int64_t forensic1394_get_device_guid(forensic1394_dev *dev)
static VALUE c_forensic1394_get_device_guid(VALUE dev){
	//TODO: write this
	return INT2FIX(forensic1394_get_device_guid(dev));
}

//g C def: const char *forensic1394_get_device_product_name(forensic1394_dev *dev)
static VALUE c_forensic1394_get_device_product_name(VALUE dev){
	//TODO: write this
	return rb_str(forensic1394_get_device_product_name(dev));
}

//g C def: const char *forensic1394_get_vendor_product_name(forensic1394_dev *dev)
static VALUE c_forensic1394_get_vendor_product_name(VALUE dev){
	//TODO: write this
	return rb_str(forensic1394_get_vendor_product_name(dev));
}

//g C def: const char* forensic1394_get_device_vendor_name(forensic1394_dev *dev)
static VALUE c_forensic1394_get_device_vendor_name(VALUE dev){
	//TODO: write this
	return rb_str(forensic1394_get_device_vendor_name(dev));
}

//g C def: int forensic1394_get_device_request_size(forensic1394_dev *dev);
static VALUE c_forensic1394_get_device_request_size(VALUE dev){
	//TODO: write this
	return INT2FIX(forensic1394_get_device_request_size(dev));
}

//g C def: const char *forensic1394_get_result_str(forensic1394_result r);
static VALUE c_forensic1394_get_result_str(VALUE r){
	//TODO: write this
	return rb_str(forensic1394_get_result_str(NUM2INT(r)));
}


VALUE cForensic;

void Init_Forensic1394() {
	cForensic = rb_define_module("Forensic1394");

	rb_define_method(cForensic,"forensic1394_enable_sbp2", forensic1394_enable_sbp2, 2);
	rb_define_method(cForensic,"forensic1394_alloc", c_forensic1394_alloc,1);
	rb_define_method(cForensic,"forensic1394_get_devices", c_forensic1394_get_devices,3);
	rb_define_method(cForensic,"forensic1394_open_device", c_forensic1394_open_device,1);
	rb_define_method(cForensic,"forensic1394_device_is_open", c_forensic1394_device_is_open,1);
	rb_define_method(cForensic,"forensic1394_read_device", c_forensic1394_read_device,4);
	rb_define_method(cForensic,"forensic1394_read_device", c_forensic1394_read_device_v,3);
	rb_define_method(cForensic,"forensic1394_write_device", c_forensic1394_write_device,4);
	rb_define_method(cForensic,"forensic1394_write_device_v", c_forensic1394_write_device_v,3);
	rb_define_method(cForensic,"forensic1394_get_device_node_id", c_forensic1394_get_device_node_id,1);
	rb_define_method(cForensic,"forensic1394_get_device_guid", c_forensic1394_get_device_guid,2);
	rb_define_method(cForensic,"forensic1394_get_device_product_name", c_forensic1394_get_device_product_name,1);
	rb_define_method(cForensic,"forensic1394_get_vendor_product_name", c_forensic1394_get_vendor_product_name,1);
	rb_define_method(cForensic,"forensic1394_get_device_vendor_name", c_forensic1394_get_device_vendor_name,1);
	rb_define_method(cForensic,"forensic1394_get_device_request_size", c_forensic1394_get_device_request_size,1);
	rb_define_method(cForensic,"forensic1394_get_result_str", c_forensic1394_get_result_str,1);
}

