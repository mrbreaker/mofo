$LOAD_PATH.unshift(File.dirname(__FILE__)) 
require 'ffi'
require 'Forensic1394'
require 'errors'
require 'device'
require 'weakref'

class Bus
    def initialize
        # Allocate a new bus handle; _as_parameter_ allows passing of self
        @as_parameter = Forensic1394.alloc()

        # Weak references to the most recent device list
        @wrefdev = []
    end

    def enable_sbp2
        # Re-raise for a cleaner stack trace
        process_result(Forensic1394.enable_sbp2(@as_parameter), 'Forensic1394.enable_sbp2')
    end

    def devices
        # Mark any active device handles as being stale
        for wdev in @wrefdev
            if wdev.to_s
                wdev.to_s.setStale(true)
            end
        end

        # Clear the current list of weak references
        @wrefdev = []
        dev = []
        ndev = FFI::Buffer.new :int
        
        # Query the list of devices attached to the system
        devlist = Forensic1394.get_devices(@as_parameter, ndev, nil)
        p = FFI::Pointer.new(devlist)
        
        devlist = p.read_array_of_pointer(ndev.get_int(0)) 

        # If ndev is < 0 then it contains a result status code
        if ndev.get_int(0) < 0
            process_result(ndev.get_int(0), "Forensic1394.get_devices")
        end

        # Create Device instances for the devices found
        for i in (0..ndev.get_int(0) - 1)
            d = Device.new(self, devlist[i])
            dev << d
            # Maintain a weak reference to this device
            @wrefdev << WeakRef.new(d)
        end
        
        # Return the device list
        return dev
    end

    def delete
        Forensic1394.destroy(@as_parameter)
    end
end
