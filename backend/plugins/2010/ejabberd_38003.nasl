###############################################################################
# OpenVAS Vulnerability Test
# $Id: ejabberd_38003.nasl 14233 2019-03-16 13:32:43Z mmartin $
#
# ejabberd 'client2server' Message Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100487");
  script_version("$Revision: 14233 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-16 14:32:43 +0100 (Sat, 16 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-02-08 23:29:56 +0100 (Mon, 08 Feb 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-0305");
  script_bugtraq_id(38003);

  script_name("ejabberd 'client2server' Message Remote Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38003");
  script_xref(name:"URL", value:"https://support.process-one.net/browse/EJAB/fixforversion/10453");
  script_xref(name:"URL", value:"http://www.process-one.net/en/ejabberd/");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("ejabberd_detect.nasl");
  script_require_ports("Services/xmpp", 5222);
  script_tag(name:"solution", value:"The vendor has released an update. Please see the references
for details.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The 'ejabberd' application is prone to a denial-of-service
vulnerability.

An attacker can exploit this issue to crash the affected application,
denying service to legitimate users.

Versions prior to ejabberd 2.1.3 are vulnerable. Other versions may
also be affected.");
  exit(0);
}

include("version_func.inc");

xmpp_port = get_kb_item("Services/xmpp");
if(!xmpp_port)xmpp_port=5222;
if(!get_port_state(xmpp_port))exit(0);

if(!version = get_kb_item(string("xmpp/", xmpp_port, "/ejabberd")))exit(0);
if(!isnull(version)) {

  if(version_is_less(version: version, test_version: "2.1.3")) {
      security_message(port:xmpp_port);
      exit(0);
  }

}

exit(0);
