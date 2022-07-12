###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_subversion_dos_vuln02.nasl 11975 2018-10-19 06:54:12Z cfischer $
#
# Apache Subversion Denial of Service Vulnerability -02 May15
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

CPE = "cpe:/a:apache:subversion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805607");
  script_version("$Revision: 11975 $");
  script_cve_id("CVE-2015-0202");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:54:12 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-05-06 12:54:14 +0530 (Wed, 06 May 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Subversion Denial of Service Vulnerability -02 May15");

  script_tag(name:"summary", value:"This host is installed with Apache Subversion
  and is prone to denial of service  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to vulnerability in mod_dav_svn
  that is triggered during the handling of certain REPORT requests, which can
  cause elements to be repeatedly allocated from a memory pool without being
  properly deallocated.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to use multiple concurrent REPORT requests to exhaust all available
  memory on the system.");

  script_tag(name:"affected", value:"Subversion 1.8.0 through 1.8.11.");

  script_tag(name:"solution", value:"Upgrade to version 1.8.13 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-updates/2015-04/msg00008.html");
  script_xref(name:"URL", value:"http://subversion.apache.org/security/CVE-2015-0202-advisory.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_subversion_remote_detect.nasl");
  script_mandatory_keys("Subversion/installed");
  script_require_ports("Services/www", 3690);
  script_xref(name:"URL", value:"https://subversion.apache.org");
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

if(version_in_range(version:subver, test_version:"1.8.0", test_version2:"1.8.11"))
{
  report = 'Installed version: ' + subver + '\n' +
           'Fixed version:     ' + "1.8.13" + '\n';
  security_message(data:report, port:http_port);
  exit(0);
}
