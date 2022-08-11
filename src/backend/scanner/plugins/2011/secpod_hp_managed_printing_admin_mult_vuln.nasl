###############################################################################
# OpenVAS Vulnerability Test
#
# HP Managed Printing Administration Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902654");
  script_version("2019-05-17T12:32:34+0000");
  script_cve_id("CVE-2011-4166", "CVE-2011-4167", "CVE-2011-4168", "CVE-2011-4169");
  script_bugtraq_id(51174);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 12:32:34 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2011-12-28 14:57:58 +0530 (Wed, 28 Dec 2011)");
  script_name("HP Managed Printing Administration Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47329/");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026456");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2011/Dec/153");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Dec/412");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-352/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-353/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-354/");
  script_xref(name:"URL", value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03128469");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to perform directory traversal
  attacks, create and read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"HP Managed Printing Administration before 2.6.4.");

  script_tag(name:"insight", value:"The flaws are due to

  - Errors in the MPAUploader.Uploader.1.UploadFiles() and MPAUploader.dll
    allows to create arbitrary files via crafted form data.

  - An improper validation of user supplied input to
  'hpmpa/jobDelivery/Default.asp' script, allows attackers to create or
  read arbitrary files via a ../(dot dot) sequences.");

  script_tag(name:"solution", value:"Upgrade to HP Managed Printing Administration version 2.6.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"This host is installed with HP Managed Printing Administration and
  is prone to multiple vulnerabilities.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

rcvRes = http_get_cache(item:"/hpmpa/home/", port:port);

if("title>HP Managed Printing Administration" >< rcvRes)
{
  hpmpaVer = eregmatch(pattern:'<dd>v([0-9.]+)<', string:rcvRes);

  if(hpmpaVer[1] != NULL)
  {
    if(version_is_less(version:hpmpaVer[1], test_version:"2.6.4"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}
