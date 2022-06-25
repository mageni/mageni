##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_diy_cms_mult_rfi_vuln.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# DiY-CMS  Multiple Remote File Inclusion Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801512");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-3206");
  script_name("DiY-CMS  Multiple Remote File Inclusion Vulnerabilities");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61454");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14822/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1008-exploits/diycms-rfi.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error in 'modules/guestbook/blocks/control.block.php', which is not
  properly validating the input passed to the 'lang' parameter.

  - An error in the 'index.php', which is not properly validating the input
  passed to 'main_module' parameter.

  - An error in the 'includes/general.functions.php', which is not properly
  validating the input passed to 'getFile' parameter.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running DiY-CMS and is prone to multiple remote
  file inclusion vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  code on the vulnerable Web server.");
  script_tag(name:"affected", value:"DiY-CMS version 1.0");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

cmsPort = get_http_port(default:80);

if(!can_host_php(port:cmsPort)){
  exit(0);
}

foreach dir (make_list_unique("/diycms/diy", "/", cgi_dirs(port:cmsPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:cmsPort);

  if("<title>Welcome - Do It Yourself CMS - Using DiY-CMS<" >< rcvRes)
  {
    cmsVer = eregmatch(pattern:"DiY-CMS ([0-9.]+)", string:rcvRes);
    if(cmsVer[1] != NULL)
    {
      if(version_is_equal(version:cmsVer[1], test_version:"1.0"))
      {
        security_message(port:cmsPort);
        exit(0);
      }
    }
  }
}

exit(99);