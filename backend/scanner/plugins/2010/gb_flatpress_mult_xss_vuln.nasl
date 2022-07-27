###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flatpress_mult_xss_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# FlatPress Multiple Cross site Scripting Vulnerabilities
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

CPE = "cpe:/a:flatpress:flatpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800284");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-01-22 09:23:45 +0100 (Fri, 22 Jan 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4461");
  script_bugtraq_id(37471);

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FlatPress Multiple Cross site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37938");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/10688");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("flatpress_detect.nasl");
  script_mandatory_keys("flatpress/installed");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attacker to execute arbitrary web
script or HTML code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"FlatPress version 0.909 and prior.");

  script_tag(name:"insight", value:"The flaws are due to error in 'contact.php', 'login.php' and 'search.php'
that fail to sufficiently sanitize user-supplied data via the PATH_INFO.");

  script_tag(name:"solution", value:"Upgrade to FlatPress version 0.909.1.");

  script_tag(name:"summary", value:"This host is running FlatPress and is prone to multiple Cross Site Scripting
vulnerabilities.");

  script_xref(name:"URL", value:"http://sourceforge.net/projects/flatpress/files/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("http_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "0.909")) {
  security_message(port: port);
  exit(0);
}

exit(99);
