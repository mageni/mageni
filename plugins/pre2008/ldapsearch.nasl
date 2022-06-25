###############################################################################
# OpenVAS Vulnerability Test
# $Id: ldapsearch.nasl 13769 2019-02-19 15:52:41Z cfischer $
#
# LDAP information extraction with ldapsearch
#
# Authors:
# Tarik El-Yassem <te@itsec.nl>
#
# Copyright (c) 2006 ITsec Security Services BV, http://www.itsec-ss.nl
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.91984");
  script_version("$Revision: 13769 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-19 16:52:41 +0100 (Tue, 19 Feb 2019) $");
  script_tag(name:"creation_date", value:"2006-04-23 14:49:44 +0200 (Sun, 23 Apr 2006)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("LDAPsearch");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2006 Tarik El-Yassem/ITsec Security Services");
  script_family("General");
  script_dependencies("toolcheck.nasl", "ldap_detect.nasl", "ldap_null_base.nasl", "ldap_null_bind.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("ldap/detected", "Tools/Present/ldapsearch");

  script_add_preference(name:"timelimit value (in seconds)", type:"entry", value:"3600");
  script_add_preference(name:"sizelimit value", type:"entry", value:"500");

  script_tag(name:"summary", value:"This plugins shows what information can be pulled of an LDAP server");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ldap.inc");

function scanopts( port, type, value, host, timelimit, sizelimit ) {

  local_var port, type, value, host, timelimit, sizelimit, i;

  i = 0;
  argv[i++] = "ldapsearch";
  argv[i++] = "-H";

  if( get_port_transport( port ) > ENCAPS_IP ) {
    ldapuri = "ldaps://" + host + ":" + port;
  } else {
    ldapuri = "ldap://" + host + ":" + port;
  }

  argv[i++] = ldapuri;
  argv[i++] = "-x"; #do not authenticate
  argv[i++] = "-C"; #we like to chase referrals (undocumented parameter)
  argv[i++] = "-b";
  argv[i++] = value;

  if( type != '' ) {
    argv[i++] = "-s";
    argv[i++] = "base";
  }

  if( type == "null-bind" ) {
    argv[i++] = "objectclass=*";
    argv[i++] = "-P3";
  }

  argv[i++] = "-l";
  argv[i++] = timelimit;
  argv[i++] = "-z";
  argv[i++] = sizelimit;

  return( argv );
}

function getdc( res ) {

  local_var res, r, n, i, patt, dc, value;

  #split string into array of smaller strings on each comma.
  r = split( res, sep:"," );
  n = 0;
  i = 0;
  patt = "dc=([a-zA-Z0-9-]+)";
  dc = eregmatch( string:r, pattern:patt, icase:TRUE );
  if( dc ) {
    value[i] = dc[n+1];
    # nb: first value of DC=... or dc=... put into our array for storage
    i++;
    n++;

    foreach line( r ) {
      if( dc[0] ) {

        #now replace the value we have already with some X-es so we won't find them again.
        r = ereg_replace( string:r, pattern:dc[0], replace:'XXXXX', icase:TRUE );

        dc = eregmatch( string:r, pattern:patt, icase:TRUE );
        value[i] = dc[n];
        # nb: the next value of dc=... or DC=...
        i++;
        if( ! dc[n] ) exit( 0 );
        n++;
      }
    }
  }
  if( ! value ) exit( 0 );
  return( value );
}

function makereport( res, args ) {

  local_var res, args, s, x;

  if( ! res ) exit( 0 );

  foreach x( args ) s = s + x + ' ';
  result = '(Command was:"' + s + '")\n\n' + res + '\n';
  return result;
}

function res_check( res ) {

  local_var res;

  if( res =~ "(S|s)uccess" && "LDAPv" >< res ) {
    return res;
  }
  else return FALSE;
}

timelimit = script_get_preference( "timelimit value (in seconds)" );
if( ! timelimit ) timelimit = 3600;
sizelimit = script_get_preference( "sizelimit value" );
if( ! sizelimit ) sizelimit = 500;

host = get_host_name();
port = get_ldap_port( default:389 );

null_base = get_kb_item( "LDAP/" + port + "/NULL_BASE" );
null_bind = get_kb_item( "LDAP/" + port + "/NULL_BIND" );
ldapv3 = is_ldapv3( port:port );

# Anonymous bind is required for LDAPv3 so try to gather infos from such an anonymous bind
if( ldapv3 ) {

  # Don't continue if we got an IPv4 or IPv6 back
  if( eregmatch( pattern:"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", string:host ) ||
      ":" >< host ) {
    exit( 0 );
  }

  # nb: Try to guess the DC/DN from the hostname
  # If we get a parly match we're getting a matchedDN: back which we can use later
  host_dn = split( host, sep:".", keep:FALSE );
  if( host_dn ) {
    first = 0;
    foreach tmp( host_dn ) {
      if( first == 0 ) {
        first = 1;
        base_dn += "dc=" + tmp;
      } else {
        base_dn += ",dc=" + tmp;
      }
    }

    args = scanopts( port:port, type:'', value:base_dn, host:host, timelimit:timelimit, sizelimit:sizelimit );
    res = pread( cmd:"ldapsearch", argv:args, nice:5 );
    tmpres = res_check( res:res );

    report = 'Grabbed the following information:\n';

    # We have a full match
    if( tmpres ) {
      report += makereport( res:res, args:args );
      log_message( port:port, data:report );
      exit( 0 );
    } else if( "matchedDN:" >< res ) {
      # nb: the base dn from the matchedDN: response
      base_dn = egrep( string:res, pattern:'^matchedDN: (.*)$', icase:TRUE );
      base_dn = ereg_replace( string:base_dn, pattern:"matchedDN: ", replace:"" );
      base_dn = chomp( base_dn );
      if( base_dn ) {
        args = scanopts( port:port, type:'', value:base_dn, host:host, timelimit:timelimit, sizelimit:sizelimit );
        res = pread( cmd:"ldapsearch", argv:args, nice:5 );
        res = res_check( res:res );
        if( res ) {
          report += makereport( res:res, args:args );
          log_message( port:port, data:report );
          exit( 0 );
        }
      }
    }
  }
} else if( null_base ) {

  #first do ldapsearch -h x.x.x.x -b '' -x -C -s base
  type = "null-base";
  value = '';
  args = scanopts( port:port, type:type, value:value, host:host, timelimit:timelimit, sizelimit:sizelimit );

  res = pread( cmd:"ldapsearch", argv:args, nice:5 );
  res = res_check( res:res );

  #this is insecure, but there's no other way to do this at the moment.
  if( res ) {
    base_report = makereport( res:res, args:args );
  }

  if( null_bind && res ) {
    #then ldapsearch -h x.x.x.x -b dc=X,dc=Y -x -C -s base 'objectclass=*' -P3 -A
    type = "null-bind";

    #this gets the dc values so we can use them for a ldapsearch down the branch..
    val = getdc( res:res );

    # nb: the first two dc values to pass it to LDAPsearch.
    value = "dc=" + val[0] + ",dc=" + val[1];

    #note that for deeper searches we would want use the other values in the array.
    #we could make this recursive so a user can specify how many branches we want to examine.
    #but then we would need to grab other things like the cn values and use those in the requests.

    args = scanopts( port:port, type:type, value:value, host:host, timelimit:timelimit, sizelimit:sizelimit );

    res = pread( cmd:"ldapsearch", argv:args, nice:5 );
    res = res_check( res:res );

    #this is insecure, but unfortunately there's no other way to do this at the moment.
    if( res ) {
      bind_report = makereport( res:res, args:args );
    }
  }

  if( bind_report || base_report ) {

    data = 'Grabbed the following information with a null-bind, null-base request:\n';

    if( bind_report == base_report ) {
     data += bind_report;
    } else {
     data += bind_report + base_report;
    }
    log_message( port:port, data:data );
  }
}

exit( 0 );