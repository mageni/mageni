###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wd_mycloud_consolidation.nasl 12584 2018-11-29 15:18:23Z cfischer $
#
# Western Digital MyCloud Products Detection Consolidation
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108488");
  script_version("$Revision: 12584 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-29 16:18:23 +0100 (Thu, 29 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-28 14:02:54 +0100 (Wed, 28 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Western Digital MyCloud Products Detection Consolidation");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_wd_mycloud_snmp_detect.nasl", "gb_wd_mycloud_ssh_login_detect.nasl", "gb_wd_mycloud_web_detect.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_xref(name:"URL", value:"https://support.wdc.com/cat_products.aspx?ID=1");

  script_tag(name:"summary", value:"The script reports a detected Western Digital MyCloud product including the
  version number and exposed services.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

if( ! get_kb_item( "wd-mycloud/detected" ) ) exit( 0 );

detected_version = "unknown";
detected_model   = "unknown";

# ssh-login: most detailed one
# snmp: offers detailed version and sometimes the model via the default hostname
# http: offers detailed model name but only the major version like 2.30
foreach source( make_list( "ssh-login", "snmp", "http" ) ) {

  version_list = get_kb_list( "wd-mycloud/" + source + "/*/version" );
  foreach version( version_list ) {
    if( version != "unknown" && detected_version == "unknown" ) {
      detected_version = version;
      set_kb_item( name:"wd-mycloud/version", value:version );
    }
  }

  model_list = get_kb_list( "wd-mycloud/" + source + "/*/model" );
  foreach model( model_list ) {
    if( model != "unknown" && detected_model == "unknown" ) {
      detected_model = model;
      set_kb_item( name:"wd-mycloud/model", value:model );
    }
  }
}

# nb: NVD is currently using various different CPEs like e.g.:
#
# cpe:/a:western_digital:mycloud_nas
# cpe:/o:wdc:my_cloud_firmware
# cpe:/h:wdc:my_cloud
# cpe:/o:wdc:my_cloud_pr4100_firmware
# cpe:/h:wdc:my_cloud_pr4100
#
# We're trying to stick with the most sane one to have the firmware registered as an OS
# including the model name as well as to register the Hardware and the model as well.

if( detected_model != "unknown" ) {
  os_app = "Western Digital MyCloud " + detected_model + " Firmware";
  os_cpe = "cpe:/o:wdc:my_cloud_" + tolower( detected_model ) + "_firmware";
  hw_app = "Western Digital MyCloud " + detected_model + " Device";
  hw_cpe = "cpe:/h:wdc:my_cloud_" + tolower( detected_model );
} else {
  os_app = "Western Digital MyCloud Unknown Model Firmware";
  os_cpe = "cpe:/o:wdc:my_cloud_unknown_model_firmware";
  hw_app = "Western Digital MyCloud Unknown Model Device";
  hw_cpe = "cpe:/h:wdc:my_cloud_unknown_model";
}

if( detected_version != "unknown" )
  os_cpe += ":" + detected_version;

register_and_report_os( os:os_app, cpe:os_cpe, desc:"Western Digital MyCloud Products Detection Consolidation", runs_key:"unixoide" );
set_kb_item(name: "wd/product/detected", value: TRUE);
location = "/";

if( ssh_login_ports = get_kb_list( "wd-mycloud/ssh-login/port" ) ) {
  foreach port( ssh_login_ports ) {

    extra += '\nSSH-Login on port ' + port + '/tcp\n';

    concluded = get_kb_item( "wd-mycloud/ssh-login/" + port + "/concluded" );
    if( concluded )
      extra += 'Concluded: ' + concluded + '\n';

    register_product( cpe:hw_cpe, location:location, port:port, service:"ssh-login" );
    register_product( cpe:os_cpe, location:location, port:port, service:"ssh-login" );
  }
}

if( http_ports = get_kb_list( "wd-mycloud/http/port" ) ) {
  foreach port( http_ports ) {

    extra += '\nHTTP(s) on port ' + port + '/tcp\n';

    concluded    = get_kb_item( "wd-mycloud/http/" + port + "/concluded" );
    concludedUrl = get_kb_item( "wd-mycloud/http/" + port + "/concludedUrl" );
    if( concluded && concludedUrl )
      extra += 'Concluded: ' + concluded + '\nfrom URL(s): ' + concludedUrl + '\n';
    else if( concluded )
      extra += 'Concluded: ' + concluded + '\n';

    register_product( cpe:hw_cpe, location:location, port:port, service:"www" );
    register_product( cpe:os_cpe, location:location, port:port, service:"www" );
  }
}

if( snmp_ports = get_kb_list( "wd-mycloud/snmp/port" ) ) {
  foreach port( snmp_ports ) {

    extra += '\nSNMP on port ' + port + '/udp\n';

    concludedVers    = get_kb_item( "wd-mycloud/snmp/" + port + "/concludedVers" );
    concludedVersOID = get_kb_item( "wd-mycloud/snmp/" + port + "/concludedVersOID" );
    if( concludedVers && concludedVersOID )
      extra += 'Concluded from: "' + concludedVers + '" via OID: "' + concludedVersOID + '"\n';

    concludedMod    = get_kb_item( "wd-mycloud/snmp/" + port + "/concludedMod" );
    concludedModOID = get_kb_item( "wd-mycloud/snmp/" + port + "/concludedModOID" );
    if( concludedMod && concludedModOID )
      extra += 'Concluded from: "' + concludedMod + '" via OID: "' + concludedModOID + '"\n';

    register_product( cpe:hw_cpe, location:location, port:port, service:"snmp", proto:"udp" );
    register_product( cpe:os_cpe, location:location, port:port, service:"snmp", proto:"udp" );
  }
}

report  = build_detection_report( app:os_app,
                                  version:detected_version,
                                  install:location,
                                  cpe:os_cpe );
report += '\n\n';
report += build_detection_report( app:hw_app,
                                  skip_version:TRUE,
                                  install:location,
                                  cpe:hw_cpe );

if( extra )
  report += '\n\nDetection methods:\n' + extra;

log_message( port:0, data:report );

exit( 0 );