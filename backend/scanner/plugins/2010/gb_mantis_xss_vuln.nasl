##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantis_xss_vuln.nasl 12818 2018-12-18 09:55:03Z ckuersteiner $
#
# MantisBT Cross-site scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801449");
  script_version("$Revision: 12818 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 10:55:03 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)");
  script_cve_id("CVE-2010-2802");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_name("MantisBT Cross-site scripting Vulnerability");
  script_xref(name:"URL", value:"http://www.mantisbt.org/blog/?p=113");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/08/03/7");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/08/02/16");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_dependencies("mantis_detect.nasl");
  script_mandatory_keys("mantisbt/detected");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);

  script_tag(name:"insight", value:"The application allows remote authenticated users to inject arbitrary web
  script or HTML via an HTML document with a '.gif' filename extension, related to inline attachments.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to MantisBT version 1.2.2 or later");

  script_tag(name:"summary", value:"This host is running MantisBT and is prone to Cross-site scripting
  Vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct cross-site scripting
  attacks.");

  script_tag(name:"affected", value:"MantisBT version prior to 1.2.2");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version:version, test_version:"1.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
