###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openfire_server_multiple_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# OpenFire Server Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:igniterealtime:openfire";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806061");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-6972", "CVE-2015-6973", "CVE-2015-7707");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-19 15:36:42 +0530 (Mon, 19 Oct 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("OpenFire Server Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with OpenFire
  Server and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Insufficient validation of input passed via the 'hostname' parameter to
    server-session-details.jsp script, 'search' parameter to group-summary.jsp
    script, 'Group Chat Name' and 'URL Name' fields in create-bookmark.jsp
    script.

  - CSRF token does not exists when making some POST and Get requests.

  - plugin-admin.jsp script does not restrict plugin files upload.

  - Insufficient validation for plugin downloads by available-plugins.jsp
    script.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site and upload and download of arbitrary files, and
  to take malicious actions against the application.");

  script_tag(name:"affected", value:"Openfire Server version 3.10.2");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38188");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38189");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38191");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38192");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openfire_detect.nasl");
  script_mandatory_keys("OpenFire/Installed");
  script_require_ports("Services/www", 9090);

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!firePort = get_app_port(cpe:CPE)){
  exit(0);
}

fireVer = get_app_version(cpe:CPE, port:firePort);
if(!fireVer || "Unknown" >< fireVer){
  exit(0);
}

if (version_is_equal(version:fireVer, test_version:"3.10.2"))
{
  report = report_fixed_ver(installed_version:fireVer, fixed_version:"WillNotFix");
  security_message(port:firePort, data:report);
  exit(0);
}

exit(99);