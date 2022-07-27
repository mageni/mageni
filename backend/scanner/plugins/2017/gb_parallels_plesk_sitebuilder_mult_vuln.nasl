###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_parallels_plesk_sitebuilder_mult_vuln.nasl 12899 2018-12-28 14:46:11Z mmartin $
#
# Parallels Plesk Sitebuilder Multiple Vulnerabilities
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

CPE = "cpe:/a:parallels:parallels_plesk_sitebuilder";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812279");
  script_version("$Revision: 12899 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-12-28 15:46:11 +0100 (Fri, 28 Dec 2018) $");
  script_tag(name:"creation_date", value:"2017-12-27 12:18:56 +0530 (Wed, 27 Dec 2017)");
  script_name("Parallels Plesk Sitebuilder Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with Parallels Plesk
  Sitebuilder and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send the crafted http	GET request
  and check whether it is able to bypass authentication or not.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Multiple input validation errors in all modules of the page 'Wizard/Edit.aspx'.

  - An improper access control on pages 'Wizard/Pages.aspx' and 'Wizard/Edit.aspx<F9>
    and loginpage.

  - Multiple input validation errors while downloading and uploading of files.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to execute arbitrary script, download and upload arbitrary files and
  bypass authentication.");

  script_tag(name:"affected", value:"Parallels Plesk Sitebuilder 4.5");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/34593");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_parallels_plesk_sitebuilder_remote_detect.nasl");
  script_mandatory_keys("Parallels/Plesk/Sitebuilder/Installed");
  script_require_ports("Services/www", 2006);
  script_xref(name:"URL", value:"http://www.parallels.com");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!ppsPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(http_vuln_check(port:ppsPort, url:"/Wizard/Default.aspx", check_header:TRUE,
                   pattern:"Copyright.*Parallels",
                   extra_check:make_list('>Design', '>Pages', '>Publish', '>Apply changes?')))
{
  report = report_vuln_url(port:ppsPort, url:"/Wizard/Default.aspx");
  security_message(port:ppsPort, data:report);
  exit(0);
}
exit(0);
