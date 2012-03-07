require 'ffi'

module Forensic1394
	extend FFI::Library
	
	ffi_lib 'forensic1394'

	# ffi_convention :stdcall
	
	#attach_function  (*forensic1394_device_callback) (forensic1394_bus *bus,forensic1394_dev *dev), :void
	#forensic1394_bus *forensic1394_alloc(void)
	attach_function :alloc,			:forensic1394_alloc, 			[ ], :pointer 

	#forensic1394_result forensic1394_enable_sbp2(forensic1394_bus *bus)
	attach_function :enable_sbp2,		:forensic1394_enable_sbp2, 		[:pointer ], :int32 

	#forensic1394_dev **forensic1394_get_devices(forensic1394_bus *bus,
	#                                            int *ndev,
	#                                            forensic1394_device_callback ondestroy)
	attach_function :get_devices,		:forensic1394_get_devices, 		[:pointer,:pointer,:pointer], :pointer

	#void forensic1394_destroy(forensic1394_bus *bus)
	attach_function :destroy,		:forensic1394_destroy, 			[:pointer ], :void 

	#forensic1394_result forensic1394_open_device(forensic1394_dev *dev)
	attach_function :open_device,		:forensic1394_open_device, 		[:pointer ], :int32

	#void forensic1394_close_device(forensic1394_dev *dev)
	attach_function :close_device,		:forensic1394_close_device, 		[:pointer ], :void 

	#int forensic1394_is_device_open(forensic1394_dev *dev)
	attach_function :is_device_open,	:forensic1394_is_device_open, 		[:pointer ], :int32 

	#forensic1394_result forensic1394_read_device(forensic1394_dev *dev,
	#                                             uint64_t addr,
	#                                             size_t len, void *buf)
	attach_function :read_device,		:forensic1394_read_device, 		[:pointer,:long_long, :uint32, :pointer ], :int32

	#forensic1394_result forensic1394_read_device_v(forensic1394_dev *dev,
	#                                               forensic1394_req *req,
	#                                               size_t nreq)
	attach_function :read_device_v,		:forensic1394_read_device_v, 		[:pointer,:pointer, :uint32 ], :int32

	#forensic1394_result forensic1394_write_device(forensic1394_dev *dev,
	#                                              uint64_t addr,
	#                                              size_t len, void *buf)
	attach_function :write_device,		:forensic1394_write_device, 		[:pointer,:long_long,:uint32, :pointer], :int32

	#forensic1394_result forensic1394_write_device_v(forensic1394_dev *dev,
	#                                                forensic1394_req *req,
	#                                                size_t nreq)
	attach_function :write_device_v,	:forensic1394_write_device_v, 		[:pointer,:pointer,:uint32], :int32

	#void forensic1394_get_device_csr(forensic1394_dev *dev, uint32_t *rom)
	attach_function :get_device_csr,	:forensic1394_get_device_csr, 		[:pointer, :pointer ], :void 

	#uint16_t forensic1394_get_device_node_id(forensic1394_dev *dev)
	attach_function :get_device_node_id,	:forensic1394_get_device_node_id, 	[:pointer ], :uint16

	#int64_t forensic1394_get_device_guid(forensic1394_dev *dev)
	attach_function :get_device_guid,	:forensic1394_get_device_guid, 		[:pointer ], :int64

	#const char *forensic1394_get_result_str(forensic1394_result r);
	attach_function :get_result_str,	:forensic1394_get_result_str, 		[:int32 ], :string

	#const char *forensic1394_get_device_product_name(forensic1394_dev *dev)
	attach_function :get_device_product_name,:forensic1394_get_device_product_name, [:pointer ], :string

    #const char *forensic1394_get_device_product_id(forensic1394_dev *dev)
	attach_function :get_device_product_id,:forensic1394_get_device_product_id, [:pointer ], :int32

	#const char *forensic1394_get_device_vendor_name(ferensic1394_dev *dev)
	attach_function :get_device_vendor_name,:forensic1394_get_device_vendor_name, [:pointer ], :string

	#int forensic1394_get_device_vendor_id(forensic1394_dev *dev)
	attach_function :get_device_vendor_id, :forensic1394_get_device_vendor_id, 	[:pointer ], :int32 

	#int forensic1394_get_device_request_size(forensic1394_dev *dev);
	attach_function :get_device_request_size,:forensic1394_get_device_request_size, [:pointer ], :int32 

	attach_function :fu, :fu, [:pointer ], :pointer


	#struct { uint64_t addr, size_t len, void *buf }
	class Req < FFI::Struct
		    layout	:addr, :uint64,
				    :len,	:uint32,
		    		:buf,	:pointer
	end
end
