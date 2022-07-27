###############################################################################
# OpenVAS Vulnerability Test
#
# Clixint DPI Image Hosting Script Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801082");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2009-12-14 09:18:47 +0100 (Mon, 14 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4252");
  script_name("Clixint DPI Image Hosting Script Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37456");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/10300");
  script_xref(name:"URL", value:"http://www.clixint.com/support/viewtopic.php?f=3&t=542");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_image_hosting_script_dpi_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("imagehostingscript/dpi/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary HTML
  script codes in a user's established login session into the context of an
  affected site running the vulnerable web application.");

  script_tag(name:"affected", value:"Image Hosting Script DPI 1.1 Final and prior on all running platforms.");

  script_tag(name:"insight", value:"This flaw is due to an error in 'images.php' which doesn't verify user supplied
  input before being used via 'date' parameter.");

  script_tag(name:"summary", value:"This host is running Image Hosting Script DPI and is prone to a Cross Site
  Scripting Vulnerability.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("http_func.inc");
include("version_func.inc");

dpiPort = get_http_port(default:80);

dpiVer = get_kb_item("www/" + dpiPort + "/ImageHostingScript/DPI");
if(!dpiVer)
  exit(0);

dpiVer = eregmatch(pattern:"^(.+) under (/.*)$", string:dpiVer);
if(dpiVer[1] != NULL)
{
  if(version_is_less_equal(version:dpiVer[1], test_version:"1.1.Final")){
    security_message(port:dpiPort, data:"The target host was found to be vulnerable.");
    exit(0);
  }
}

exit(99);
