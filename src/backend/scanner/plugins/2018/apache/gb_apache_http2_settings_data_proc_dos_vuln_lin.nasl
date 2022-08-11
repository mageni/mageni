###############################################################################
# OpenVAS Vulnerability Test
#
# Apache HTTPD HTTP/2 'SETTINGS' Data Processing DoS Vulnerability (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814056");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-11763");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-09-28 11:02:47 +0530 (Fri, 28 Sep 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache HTTPD HTTP/2 'SETTINGS' Data Processing DoS Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running Apache HTTP Server
  and is prone to denial-of-service vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper processing of
  specially crafted and continuous SETTINGS data for an ongoing HTTP/2 connection
  to cause the target service to fail to timeout.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (DoS) condition on a targeted system.");

  script_tag(name:"affected", value:"Apache HTTP Server versions 2.4.34, 2.4.33,
  2.4.30, 2.4.29, 2.4.28, 2.4.27, 2.4.26, 2.4.25, 2.4.23, 2.4.20, 2.4.18.");

  script_tag(name:"solution", value:"Upgrade to Apache HTTP Server 2.4.35 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://httpd.apache.org");
  script_xref(name:"URL", value:"https://securitytracker.com/id/1041713");
  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!httpd_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:httpd_port, exit_no_version:TRUE)) exit(0);
httpd_ver = infos['version'];
path = infos['location'];

if(httpd_ver =~ "^2\.4")
{
  foreach affected_version (make_list("2.4.18", "2.4.20", "2.4.23", "2.4.25",
           "2.4.26", "2.4.27", "2.4.28", "2.4.29", "2.4.30", "2.4.33", "2.4.34"))
  {
    if(affected_version == httpd_ver)
    {
      report = report_fixed_ver(installed_version:httpd_ver, fixed_version:"2.4.35", install_path:path);
      security_message(data:report, port:httpd_port);
      exit(0);
    }
  }
}
exit(0);
