###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_merak_mail_server_script_inj_vuln.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# Merak Mail Server Web Mail IMG HTML Tag Script Insertion Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:icewarp:mail_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800097");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-01-09 13:48:55 +0100 (Fri, 09 Jan 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2008-5734");

  script_name("Merak Mail Server Web Mail IMG HTML Tag Script Insertion Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32770");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/47533");
  script_xref(name:"URL", value:"http://blog.vijatov.com/index.php?itemid=11");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_icewarp_web_detect.nasl");
  script_mandatory_keys("icewarp/installed");

  script_tag(name:"impact", value:"Successful exploitation could result in insertion of arbitrary HTML and
script code via a specially crafted email in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Merak Mail Server 9.3.2 and prior.");

  script_tag(name:"solution", value:"Upgrade to Merak Mail Server 9.4.0");

  script_tag(name:"summary", value:"The host is running Merak Mail Server and is prone to script injection
vulnerability. Input passed via <IMG> HTML tags in emails are not properly sanitised before being displayed in
the users system.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE, service: "www"))
  exit(0);

if (!merakVer = get_app_version(cpe:CPE, port:port))
  exit(0);

if (version_is_less(version: merakVer, test_version: "9.4.0")) {
  report = report_fixed_ver(installed_version: merakVer, fixed_version: "9.4.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
