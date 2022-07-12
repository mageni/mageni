###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_apic_em_web_detect.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Cisco Application Policy Infrastructure Controller Enterprise Module Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105536");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13659 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-02-11 12:25:49 +0100 (Thu, 11 Feb 2016)");
  script_name("Cisco Application Policy Infrastructure Controller Enterprise Module Detection");

  script_tag(name:"summary", value:"This Script performs HTTP(s) based detection of Cisco Application Policy Infrastructure Controller Enterprise Module.
  When HTTP(s) credentials are given, the script is able to extract version and patch information from the application.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_add_preference(name:"APIC Username: ", value:"", type:"entry");
  script_add_preference(name:"APIC Password: ", type:"password", value:"");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:443 );

buf = http_get_cache( port:port, item:"/" );

if( "<title>Home - APIC - Enterprise Module</title>" >!< buf || "APIC-EM" >!< buf ) exit( 0 );

set_kb_item( name:"cisco/apic_em/installed", value:TRUE );

user = script_get_preference( "APIC Username: " );
pass = script_get_preference( "APIC Password: " );

cpe = 'cpe:/a:cisco:application_policy_infrastructure_controller_enterprise_module';

if( user && pass )
{
  login_credentials = TRUE;
  host = http_host_name( port:port );
  useragent = http_get_user_agent();
  data = '{"username":"' + user + '","password":"' + pass + '"}';

  len = strlen( data );

  req = 'POST /grapevine/api/auth/login HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Accept: application/json, text/javascript, */*; q=0.01\r\n' +
        'Accept-Language: en-US,en;q=0.5\r\n' +
        'Accept-Encoding: identify\r\n' +
        'Content-Type: application/json; charset=UTF-8\r\n' +
        'token: undefined\r\n' +
        'X-Requested-With: XMLHttpRequest\r\n' +
        'Content-Length: ' + len + '\r\n' +
        'Connection: close\r\n' +
        '\r\n' +
        data;

  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( "success" >< buf )
  {
    login_success = TRUE;
    _token = eregmatch( pattern:'"token": "([^"]+)"', string:buf );
    if( ! isnull( _token[1] ) ) token = _token[1];

    if( token )
    {
      req = 'GET /grapevine/api/release/current HTTP/1.1\r\n' +
            'Host: ' + host + '\r\n' +
            'User-Agent: ' + useragent + '\r\n' +
            'Accept: */*\r\n' +
            'Accept-Language: en-US,en;q=0.5\r\n' +
            'Accept-Encoding: identify\r\n' +
            'Content-Type: application/json; charset=UTF-8\r\n' +
            'token: ' + token + '\r\n' +
            'X-Requested-With: XMLHttpRequest\r\n' +
            'Connection: close\r\n\r\n';

      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

      if( "success" >< buf )
      {
        version = eregmatch( pattern:'APIC-EM apic-GA Release ([0-9.]+[^ ]+)', string:buf );
        if( ! isnull( version[1] ) )
        {
          vers = version[1];
          cpe += ':' + vers;
          set_kb_item( name:"cisco/apic_em/version", value:vers );
        }

        js_data = split( buf, sep:'"services": {', keep:FALSE );
        if( ! isnull( js_data[1] ) )
        {
          services = split( js_data[1], sep:",", keep:FALSE );
          if( services )
          {
            foreach s ( services )
            {
              s = ereg_replace( string:s, pattern:'[ "}]', replace:'' );
              line += s + ' ';
            }
            # Example:
            # reverse-proxy:0.3.0.638 scheduler-service:0.9.5.2155 cas-service:0.3.0.638 task-service:0.9.5.2155 apic-em-pki-broker-service:0.9.5.2155 policy-analysis-service:0.9.5.2155 rbac-service:0.3.0.638 apic-em-inventory-manager-service:0.9.5.2147 apic-em-event-service:0.9.5.2147 policy-manager-service:0.9.5.2155 apic-em-jboss-ejbca:0.9.5.2155 pfr-policy-programmer-service:0.9.6.6149 remote-ras:0.9.5.2155 log-aggregator:0.1.1.301 ip-pool-manager-service:0.9.6.6149 election-service:0.3.0.638 nbar-policy-programmer-service:0.9.6.6149 postgres:0.9.5.2155 pnp-service:0.9.5.2155 ipgeo-service:0.9.6.6149 router:0.3.0.638 qos-policy-programmer-service:0.9.5.2155 telemetry-service:0.9.5.2155 file-service:0.9.5.2155 visibility-service:0.9.6.6149 data-access-service:0.9.5.2155 ui:0.9.5.2155 topology-service:0.9.5.2155 apic-em-network-programmer-service:0.9.5.2147 app-vis-policy-programmer-service:0.9.6.6149 version:1.0.3.4 update:unavailable
            if( line ) set_kb_item( name:"cisco/apic_em/installed_services", value:line );
          }
        }
      }
    }
  }
}

report = 'Detected Cisco Application Policy Infrastructure Controller Enterprise Module\n';

if( ! vers && line )
{
  version = eregmatch( pattern:' version:([0-9.]+[^ ]+) ', string:line );
  if( ! isnull( version[1] ) )
  {
    vers = version[1];
    cpe += ':' + vers;
    set_kb_item( name:"cisco/apic_em/version", value:vers );
  }
}

if( vers )
  report += 'Version: ' + vers + '\n';
else
{
  if( login_credentials )
    if( login_success )
      extra_report = '\n\n** The scanner was able to login but failed to get the version **.\n\n';
    else
      extra_report = '\n\n** The scanner was not able to login using the given credentials **.\n\n';
  else
    extra_report = '\n\n** No HTTP(s) credentials where given. Scanner was not able to to extract version and patch information from the application. **\n\n';
}

report += 'CPE: ' + cpe + '\n';
report += 'Location: /';

if( extra_report ) report += extra_report;

register_product( cpe:cpe, location:"/", port:port );

log_message( port:port, data:report );

exit( 0 );