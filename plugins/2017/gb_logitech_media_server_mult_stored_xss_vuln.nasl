###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_logitech_media_server_mult_stored_xss_vuln.nasl 12902 2018-12-28 17:46:06Z cfischer $
#
# Logitech Media Server Multiple Persistent XSS Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:logitech:media_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811895");
  script_version("$Revision: 12902 $");
  script_cve_id("CVE-2017-16568", "CVE-2017-16567");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-28 18:46:06 +0100 (Fri, 28 Dec 2018) $");
  script_tag(name:"creation_date", value:"2017-11-07 14:00:28 +0530 (Tue, 07 Nov 2017)");
  script_name("Logitech Media Server Multiple Persistent XSS Vulnerabilities");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_logitech_media_server_consolidation.nasl");
  script_mandatory_keys("logitech/squeezecenter/version");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43123");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43122");

  script_tag(name:"summary", value:"This host is running Logitech Media Server
  and is prone to multiple stored cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an insufficient
  validation of user supplied input via new favorite field value in favorites
  tab and new URL value in Radio URL tab.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  users to execute arbitrary script code in the browser of an unsuspecting user
  in the context of the affected site. This may allow the attacker to steal
  cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Logitech Media Server version 7.9.0.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(vers == "7.9.0"){
  report = report_fixed_ver(installed_version:vers, fixed_version:"WillNotFix");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);