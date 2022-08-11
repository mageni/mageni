###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_siemens_scalance_multiple_vuln_05_13.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# Siemens Scalance X200 Series Switches Multiple Vulnerabilities.
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103724");
  script_bugtraq_id(60168, 60165);
  script_cve_id("CVE-2013-3634", "CVE-2013-3633");
  script_tag(name:"cvss_base", value:"8.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:C");
  script_version("$Revision: 13624 $");

  script_name("Siemens Scalance X200 Series Switches Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://subscriber.communications.siemens.com/");
  script_xref(name:"URL", value:"http://www.siemens.com/corporate-technology/pool/de/forschungsfelder/siemens_security_advisory_ssa-170686.pdf");

  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-05-30 17:50:28 +0200 (Thu, 30 May 2013)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("General");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");

  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports(23);
  script_mandatory_keys("telnet/siemens/scalance_x200/detected");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory
  for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Siemens Scalance X200 series switches are prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  1. a remote security bypass vulnerability.

  An attacker can exploit this issue to bypass certain security
  restrictions and execute SNMP commands without proper credentials.

  2. a remote privilege-escalation vulnerability.

  An attacker can exploit this issue to gain elevated privileges
  within the application and execute commands with escalated privileges.");

  exit(0);
}

include("telnet_func.inc");
include("version_func.inc");

port = 23;
if(!get_port_state(port))exit(0);
banner = get_telnet_banner(port:port);

if(!banner || "SCALANCE X200" >!< banner || "Device type" >!< banner || "Firmware" >!< banner)
  exit(0);

dv = eregmatch(pattern:string("Device type.*:.*SCALANCE ([^\r\n ]+)"), string:banner);
if(isnull(dv[1]))exit(0);

device = dv[1];

vuln_devices = make_list("X204","X202-2","X201-3","X200-4");

foreach vd (vuln_devices) {

  if(vd == device) {
    affected_device = TRUE;
    break;
  }
}

if(!affected_device)exit(0);

fw = eregmatch(pattern:string("Firmware.*: V ([^\r\n ]+)"), string:banner);
if(isnull(fw[1]))exit(0);

firmware = fw[1];

if(version_is_less(version:firmware, test_version:"5.1.0")) {
  security_message(port:port);
  exit(0);
}

exit(99);