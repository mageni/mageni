##############################################################################
# OpenVAS Vulnerability Test
# Description: MySQL Empty Bit-String Literal Denial of Service Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900221");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
  script_bugtraq_id(31081);
  script_cve_id("CVE-2008-3963");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("MySQL Empty Bit-String Literal Denial of Service Vulnerability");

  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed");
  script_xref(name:"URL", value:"http://secunia.com/advisories/31769/");
  script_xref(name:"URL", value:"http://bugs.mysql.com/bug.php?id=35658");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-26.html");
  script_tag(name:"summary", value:"This host is running MySQL, which is prone to Denial of Service
  Vulnerability.");
  script_tag(name:"insight", value:"Issue is due to error while processing an empty bit string literal via
  a specially crafted SQL statement.");
  script_tag(name:"affected", value:"MySQL versions prior to 5.0.x - 5.0.66,
  5.1.x - 5.1.26, and 6.0.x - 6.0.5 on all running platform.");
  script_tag(name:"solution", value:"Update to version 5.0.66 or 5.1.26 or 6.0.6 or later.");
  script_tag(name:"impact", value:"Successful exploitation by remote attackers could cause denying
  access to legitimate users.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE))
  exit(0);

if(!mysqlVer = get_app_version(cpe:CPE, port:sqlPort))
  exit(0);

if(ereg(pattern:"^(5\.0(\.[0-5]?[0-9]|\.6[0-5])?|5\.1(\.[01]?[0-9]|" +
                "\.2[0-5])?|6\.0(\.[0-5])?)[^.0-9]", string:mysqlVer)){
  security_message(port:sqlPort);
}