###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_imanager_2_7_4.nasl 13952 2019-03-01 08:30:06Z ckuersteiner $
#
# Novell iManager < 2.7.4 Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.100692");
  script_version("$Revision: 13952 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 09:30:06 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-06-24 12:53:20 +0200 (Thu, 24 Jun 2010)");
  script_bugtraq_id(40480, 40485);
  script_cve_id("CVE-2010-1929", "CVE-2010-1930");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Novell iManager < 2.7.4 Multiple Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/40480");
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/40485");
  script_xref(name:"URL", value:"http://www.coresecurity.com/content/novell-imanager-buffer-overflow-off-by-one-vulnerabilities");
  script_xref(name:"URL", value:"http://www.novell.com/products/consoles/imanager/features.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("novell_imanager_detect.nasl");
  script_require_ports("Services/www", 8080, 8443);
  script_mandatory_keys("novellimanager/installed");

  script_tag(name:"summary", value:"Novell iManager is prone to multiple Vulnerabilities.

  - A stack-based buffer-overflow vulnerability because it fails to perform adequate boundary checks on
    user-supplied data. Attackers may exploit this issue to execute arbitrary code with SYSTEM-level privileges.
    Successful exploits will completely compromise affected computers. Failed exploit attempts will result in a
    denial-of-service condition.

  - A denial-of-service vulnerability due to an off-by-one error. Attackers may exploit this issue to crash the
   affected application, denying service to legitimate users.

  Versions prior to Novell iManager 2.7.4 are vulnerable.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = make_list( "cpe:/a:novell:imanager", "cpe:/a:netiq:imanager" );

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.7.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
