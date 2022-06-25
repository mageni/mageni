###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_subversion_info_disclose_vuln_feb16.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Apache Subversion Insecure Authentication Weakness Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:subversion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806861");
  script_version("$Revision: 12313 $");
  script_cve_id("CVE-2014-3528");
  script_bugtraq_id(68995);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-02-09 11:07:36 +0530 (Tue, 09 Feb 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Subversion Insecure Authentication Weakness Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Apache Subversion
  and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to Usage of MD5 hash of the
  URL and authentication realm to store cached credentials.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to obtain the credentials via a crafted authentication
  realm without also checking the server's URL.");

  script_tag(name:"affected", value:"1.0.0 through 1.7.x before 1.7.17
  and 1.8.x before 1.8.10");

  script_tag(name:"solution", value:"Upgrade to version 1.7.17, or 1.8.10,
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://subversion.apache.org/security/CVE-2014-3528-advisory.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_subversion_remote_detect.nasl");
  script_mandatory_keys("Subversion/installed");
  script_require_ports("Services/www", 3690);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!subver = get_app_version(cpe:CPE, port:http_port)){
  exit(0);
}

if(subver =~ "^(1\.8)")
{
  if(version_is_less(version:subver, test_version:"1.8.10"))
  {
     report = report_fixed_ver( installed_version:subver, fixed_version:"1.8.10" );
     security_message(data:report, port:http_port);
     exit(0);
  }
}

else if(subver =~ "^(1\.)")
{
  if(version_is_less(version:subver, test_version:"1.7.17"))
  {
     report = report_fixed_ver( installed_version:subver, fixed_version:"1.7.17" );
     security_message(data:report, port:http_port);
     exit(0);
  }
}
