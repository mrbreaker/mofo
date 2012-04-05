# -*- coding: utf-8 -*-
#############################################################################
#  This file is part of libforensic1394.                                    #
#  Copyright.new(C) 2010  Freddie Witherden <freddie@witherden.org>         #
#                                                                           #
#  libforensic1394 is free software: you can redistribute it and/or modify  #
#  it under the terms of the GNU Lesser General Public License as           #
#  published by the Free Software Foundation, either version 3 of the       #
#  License, or(at your option) any later version.                           #
#                                                                           #
#  libforensic1394 is distributed in the hope that it will be useful,       #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of           #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            #
#  GNU Lesser General Public License for more details.                      #
#                                                                           #
#  You should have received a copy of the GNU Lesser General Public         #
#  License along with libforensic1394.  If not, see                         #
#  <http://www.gnu.org/licenses/>.                                          #
#############################################################################
$LOAD_PATH.unshift(File.dirname(__FILE__)) 
require 'errors'
require 'Forensic1394'
require 'ffi'
require 'pp'
class Device
    ##
    # Constructs a new Device instance.  This should not usually be called
    # directly; instead a list of pre-constructed Device instances should be
    # requested from the bus.
    
    def initialize (bus, devptr)
        # Retain a reference to the Bus.new(otherwise unused)
        @bus = bus
        
        # Used to point to the device object
        @devptr = devptr
        
        # We are not stale
        @stale = false
        
        # Copy over the device properties
        @node_id = Forensic1394.get_device_node_id(@devptr)
        @guid = Forensic1394.get_device_guid(@devptr)
        
        @product_name = Forensic1394.get_device_product_name(@devptr)
        @product_id = Forensic1394.get_device_product_id(@devptr)
        
        @vendor_name = Forensic1394.get_device_vendor_name(@devptr)
        @vendor_id = Forensic1394.get_device_vendor_id(@devptr)
        @request_size = Forensic1394.get_device_request_size(@devptr)
        
        @csr = FFI::Buffer.new(4, 256, true)
        Forensic1394.get_device_csr(@devptr, @csr)
    end
    
    def checkStale
        if @stale
            raise Forensic1394StaleHandle
        end
    end

    def setStale(stale)
        @stale = stale
    end

    ##
    # Attempts to open the device.  If the device can not be opened, or if the
    # device is stale, an exception raised.
    
    def open
        checkStale()
        process_result(Forensic1394.open_device(@devptr), 'Forensic1394.open_device')
    end
    
    ##
    # Closes the device.  If the device is stale this is a no-op
    
    def close
        if not @stale
            Forensic1394.close_device(@devptr)
        end
    end
    
    ##
    # Checks to see if the device is open or not, returning a boolean value.
    # In the case of a stale handle false is returned.
    
    def isOpen
        if @stale
            return false
        else
            return Forensic1394.is_device_open(@devptr)
        end
    end

    ## 
    # Attempts to read numb bytes from the device starting at addr.
    # The device must be open and the handle can not be stale.
    # Requests larger than @request_size will automatically be
    # broken down into smaller chunks.  The resulting data is
    # returned. 
    
    def read (addr, numb)
        # Break the request up into rs size chunks; if numb % rs = 0 then
        # lens may have an extra element; zip will take care of this
        rs = @request_size
        addrs = (addr..addr + numb).step(rs)
        lens = [rs] * (Integer(numb) / Integer(rs)) + [numb % rs]
        return readreq(addrs.zip(lens))
        #buf = FFI::Buffer.new(1, numb, true)
        #readreq(addrs.zip(lens), buf)
        #return buf.get_bytes(0,numb)
    end
    
    ##
    # Attempts to write buf.length bytes to the device starting at addr.  The
    # device must be open and the handle can not be stale.  Requests larger
    # than @request_size will automatically be broken down into smaller
    # chunks.  Uses writev internally.
    
    def write (addr, buf)
        checkStale()
        # Break up the request
        req = []
        (0..buf.size).step(@request_size) do |off|
            if (buf.size - off < @request_size)
                req << [addr + off, buf.slice(off, buf.size % @request_size)]
            end
            req << [addr + off, buf.slice(off, @request_size)]
        end 
         
        # Dispatch
        writev(req)
    end
    
    def writev (req)
        checkStale()
        if isOpen() == 0
            raise "Forensic1394Exception", "not open"
        end
       
        # Prepare the request array(addr, len, buf)
        for addr, buf in req
            creq = Forensic1394::Req.new()
	    b = FFI::MemoryPointer.new(:char,buf.size);
	    b.write_array_of_char(buf.to_s)

            creq[:addr]=addr
            creq[:len]=buf.size
            creq[:buf]= b
            process_result(Forensic1394.write_device_v(@devptr, creq, 1), 'Forensic1394.write_device')
        end  
    end
    
    ##
    # The node ID of the device on the bus.
    
    def node_id
       return @node_id
    end
    
    ## 
    # The 48-bit GUID of the device.
    
    def guid
        return @guid
    end
    
    ## 
    # The product name of the device; may be ''.
    
    def product_name
        return @product_name
    end
    
    ## 
    # The product id of the device; integer.

    def product_id
        return @product_id
    end
    
    ## 
    # The vendor name of the device; may be ''.
    
    def vendor_name
        return @vendor_name
    end
    
    ## 
    # The vendor id of the device; integer.
    
    def vendor_id
        return @vendor_id
    end
    
    ## 
    # The maximum request size supported by the device in bytes; this is
    # always a power of two.
    
    def request_size
        return @request_size
    end
    
    ## 
    # Configuration status ROM for the device, list of 32-bit host-endian
    # integers.
    
    def csr
        return @csr
    end

    private
    
    ##
    # Internal low level read function.
    
    def readreq(req)
        if isOpen() == 0
            raise Forensic1394Exception, "not open"
        end
         
        off = 0 
        buf = ""	
        for addr, numb in req
            #set up the struct for passing
            creq = Forensic1394::Req.new
            creq[:addr] = addr
            creq[:len]=numb
            
	    b = FFI::MemoryPointer.new(:char,numb)
	    creq[:buf]= b
 
            # Dispatch the request
            status = Forensic1394.read_device_v(@devptr, creq, 1)
	    buff += b.read_array_of_char()
            
            process_result(status, "Forensic1394.read_device_v")
            off += numb
        end
	return buff
    end
end
