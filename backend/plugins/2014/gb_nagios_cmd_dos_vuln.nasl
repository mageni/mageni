##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagios_cmd_dos_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Nagios cmd.cgi Denial Of Service Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/a:nagios:nagios";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804248");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-1878");
  script_bugtraq_id(65605);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-03-18 12:05:18 +0530 (Tue, 18 Mar 2014)");
  script_name("Nagios cmd.cgi Denial Of Service Vulnerability");


  script_tag(name:"summary", value:"This host is running Nagios and is prone to denial of service vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw exists in cmd_submitf() function in cmd.cgi which fails to adequately
bounds-check user-supplied data before copying it into buffer");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
or cause denial of service condition.");
  script_tag(name:"affected", value:"Nagios version before 4.0.3rc1 are affected.");
  script_tag(name:"solution", value:"Upgrade to version Nagios version 4.0.3rc1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57024");
  script_xref(name:"URL", value:"http://www.cnnvd.org.cn/vulnerability/show/cv_id/2014020484");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("nagios_detect.nasl");
  script_mandatory_keys("nagios/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.nagios.org");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ver = get_app_version(cpe:CPE, port:http_port)){
  exit(0);
}

if(version_is_less_equal(version:ver, test_version:"4.0.3"))
{
  security_message(http_port);
  exit(0);
}
