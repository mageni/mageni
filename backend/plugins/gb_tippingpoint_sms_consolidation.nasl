# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108566");
  script_version("2019-04-25T14:20:04+0000");
  script_tag(name:"last_modification", value:"2019-04-25 14:20:04 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-25 08:00:03 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("TrendMicro TippingPoint Security Management System (SMS) Detection Consolidation");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH");
  script_dependencies("gb_tippingpoint_sms_http_detect.nasl", "gb_tippingpoint_sms_ssh_login_detect.nasl", "gb_tippingpoint_sms_snmp_detect.nasl");
  script_mandatory_keys("tippingpoint/sms/detected");

  script_xref(name:"URL", value:"https://www.trendmicro.com/en_us/business/products/network/intrusion-prevention/centralized-management-response.html");

  script_tag(name:"summary", value:"The script reports a detected a TrendMicro TippingPoint Security Management System (SMS) including the
  version number and exposed services.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

if( ! get_kb_item( "tippingpoint/sms/detected" ) )
  exit( 0 );

detected_version = "unknown";

foreach source( make_list( "ssh-login", "snmp", "http" ) ) {

  version_list = get_kb_list( "tippingpoint/sms/" + source + "/*/version" );
  foreach version( version_list ) {
    if( version != "unknown" && detected_version == "unknown" ) {
      detected_version = version;
      set_kb_item( name:"tippingpoint/sms/version", value:version );
    }
  }
}

if( detected_version != "unknown" )
  app_cpe = "cpe:/a:trendmicro:tippingpoint_security_management_system:" + detected_version;
else
  app_cpe = "cpe:/a:trendmicro:tippingpoint_security_management_system";

os_cpe  = "cpe:/o:trendmicro:tippingpoint_operating_system";
os_name = "TrendMicro TippingPoint Operating System (TOS)";

register_and_report_os( os:os_name, cpe:os_cpe, desc:"TrendMicro TippingPoint Security Management System (SMS) Detection Consolidation", runs_key:"unixoide" );

location = "/";

if( ssh_login_ports = get_kb_list( "tippingpoint/sms/ssh-login/port" ) ) {
  foreach port( ssh_login_ports ) {
    concluded  = get_kb_item( "tippingpoint/sms/ssh-login/" + port + "/concluded" );
    extra     += '\nSSH-Login on port ' + port + '/tcp\n';
    if( concluded ) {
      extra += 'Concluded: ' + concluded + '\n';
    }
    register_product( cpe:app_cpe, location:location, port:port, service:"ssh-login" );
    register_product( cpe:os_cpe, location:location, port:port, service:"ssh-login" );
  }
}

if( http_ports = get_kb_list( "tippingpoint/sms/http/port" ) ) {
  foreach port( http_ports ) {
    concluded     = get_kb_item( "tippingpoint/sms/http/" + port + "/concluded" );
    concludedUrl  = get_kb_item( "tippingpoint/sms/http/" + port + "/concludedUrl" );
    extra        += '\nHTTP(s) on port ' + port + '/tcp\n';
    if( concluded && concludedUrl ) {
      extra += 'Concluded: ' + concluded + ' from URL: ' + concludedUrl + '\n';
    } else if( concluded ) {
      extra += 'Concluded: ' + concluded + '\n';
    }
    register_product( cpe:app_cpe, location:location, port:port, service:"www" );
    register_product( cpe:os_cpe, location:location, port:port, service:"www" );
  }
}

if( snmp_ports = get_kb_list( "tippingpoint/sms/snmp/port" ) ) {
  foreach port( snmp_ports ) {
    concluded  = get_kb_item( "tippingpoint/sms/snmp/" + port + "/concluded" );
    extra     += '\nSNMP on port ' + port + '/udp\n';
    if( concluded ) {
      extra += 'Concluded from SNMP SysDesc: ' + concluded + '\n';
    }
    register_product( cpe:app_cpe, location:location, port:port, service:"snmp", proto:"udp" );
    register_product( cpe:os_cpe, location:location, port:port, service:"snmp", proto:"udp" );
  }
}

report  = build_detection_report( app:"TrendMicro TippingPoint Security Management System (SMS)",
                                  version:detected_version,
                                  install:location,
                                  cpe:app_cpe );
report += '\n\n';
report += build_detection_report( app:os_name,
                                  skip_version:TRUE,
                                  install:location,
                                  cpe:os_cpe );

if( extra ) {
  report += '\n\nDetection methods:\n';
  report += extra;
}

log_message( port:0, data:report );

exit( 0 );