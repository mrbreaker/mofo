#############################################################################
#  This file is part of libforensic1394.                                    #
#  Copyright (C) 2010  Freddie Witherden <freddie@witherden.org>            #
#                                                                           #
#  libforensic1394 is free software: you can redistribute it and/or modify  #
#  it under the terms of the GNU Lesser General Public License as           #
#  published by the Free Software Foundation, either version 3 of the       #
#  License, or (at your option) any later version.                          #
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

#  Possible result codes from a forensic1394 function call.  These are
#  extracted from the forensic1394.h file.

class ResultCode
    SUCCESS     = 0
    OTHERERROR  = -1
    BUSRESET    = -2
    NOPERM      = -3
    BUSY        = -4
    IOERROR     = -5
    IOSIZE      = -6
    IOTIMEOUT   = -7
end

class Forensic1394Exception < Exception
end
    
class Forensic1394ImportError < LoadError
end

class Forensic1394BusReset < IOError
end

class Forensic1394StaleHandle < IOError
end

def process_result(result, fname)
    # Call was successful
    if result == ResultCode::SUCCESS
        return
    end
    
    # Maybe decode?
    err = fname + ": " + Forensic1394.get_result_str(result)

    # Decide which exception to throw
    if result == ResultCode::BUSRESET
        raise Forensic1394BusReset, err
    else
        raise IOError, err
    end
end

