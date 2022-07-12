###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ssh_junos_get_version.nasl 8007 2017-12-06 09:50:38Z ckuersteiner $
#
# Get Junos Software Version
#
# Authors:
# Thomas Rotter <thomas.rotter@greenbone.net>
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96200");
  script_version("$Revision: 8007 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-06 10:50:38 +0100 (Wed, 06 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-07-13 11:48:37 +0200 (Wed, 13 Jul 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Get Junos Software Version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl", "gb_junos_snmp_version.nasl");
  script_mandatory_keys("junos/detected");

  script_tag(name:"summary", value:"This script performs SSH based detection of Junos Software Version.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

soc = ssh_login_or_reuse_connection();
if(!soc)exit(0);

if( get_kb_item( "junos/cli" ) )
  sysversion = ssh_cmd(socket:soc, cmd:'show version detail | no-more', nosh:TRUE );
else
  sysversion = ssh_cmd(socket:soc, cmd:'cli show version detail \\| no-more');

if( ! sysversion || "JUNOS" >!< sysversion ) exit(0);

set_kb_item( name:"junos/show_version", value:sysversion );

v = eregmatch(pattern: 'Junos: ([^\r\n]+)', string: sysversion);
if( isnull( v[1] ) ) {
  v = eregmatch( pattern:"KERNEL ([^ ]+) .+on ([0-9]{4}-[0-9]{2}-[0-9]{2})", string:sysversion );
  if (isnull(v[1]))
    exit( 0 );
}

version = v[1];

b = eregmatch( pattern:"KERNEL ([^ ]+) .+on ([0-9]{4}-[0-9]{2}-[0-9]{2})", string:sysversion );
if (!isnull(b[2]))
  build = b[2];

cpe = "cpe:/o:juniper:junos:" + version;

m = eregmatch( pattern:'Model: ([^\r\n]+)', string:sysversion );
if( ! isnull ( m[1] ) )
{
  model = m[1];
  set_kb_item(name: "Junos/model", value:model );
}

set_kb_item(name: "Junos/Version", value:version);
set_kb_item(name: "Junos/Build", value:build);

register_and_report_os( os:"JunOS", cpe:cpe, banner_type:"SSH login", desc:"Get Junos Software Version", runs_key:"unixoide" );

register_product( cpe:cpe, location:'ssh' );

report = "Your Junos Version is: " + version + '\n';
if( build ) report += "Build: " + build + '\n';

report += "CPE: " + cpe + '\n';

if( model ) report += "Model: " + model;

log_message(port:0, data:report);
exit(0);

