###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Web Server ETag Header Information Disclosure Weakness
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if (description)
{
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/6939");
  script_xref(name:"URL", value:"http://httpd.apache.org/docs/mod/core.html#fileetag");
  script_xref(name:"URL", value:"http://www.openbsd.org/errata32.html");
  script_xref(name:"URL", value:"http://support.novell.com/docs/Tids/Solutions/10090670.html");
  script_oid("1.3.6.1.4.1.25623.1.0.103122");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2011-03-21 17:38:45 +0100 (Mon, 21 Mar 2011)");
  script_bugtraq_id(6939);
  script_cve_id("CVE-2003-1418");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Apache Web Server ETag Header Information Disclosure Weakness");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/banner", "ETag/banner");

  script_tag(name:"summary", value:"A weakness has been discovered in Apache web servers that are
  configured to use the FileETag directive.");

  script_tag(name:"vuldetect", value:"Due to the way in which
  Apache generates ETag response headers, it may be possible for an
  attacker to obtain sensitive information regarding server files.
  Specifically, ETag header fields returned to a client contain the
  file's inode number.");

  script_tag(name:"impact", value:"Exploitation of this issue may provide an attacker with information
  that may be used to launch further attacks against a target network.");

  script_tag(name:"solution", value:"OpenBSD has released a patch that addresses this issue. Inode numbers
  returned from the server are now encoded using a private hash to avoid
  the release of sensitive information.

  Novell has released TID10090670 to advise users to apply the available
  workaround of disabling the directive in the configuration file for
  Apache releases on NetWare. Please see the attached Technical
  Information Document for further details.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner || "Apache" >!< banner || "ETag" >!< banner)exit(0);

etag = eregmatch(pattern:'ETag: "([^"]+)"', string:banner);
if(isnull(etag[1]))exit(0);

etag = split(etag[1], sep:"-",keep:FALSE);
if((max_index(etag)<3))exit(0);

inode = string("0x",etag[0]);
size  = string("0x",etag[1]);

inode = (hex2dec(xvalue:inode));
size  = (hex2dec(xvalue:size));

report = string("Information that was gathered:\nInode: ", inode,"\nSize: ", size,"\n");

security_message(port:port,data:report);

exit(0);