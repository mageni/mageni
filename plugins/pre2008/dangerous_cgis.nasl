###############################################################################
# OpenVAS Vulnerability Test
#
# Various dangerous cgi scripts
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
# Some entries were added by David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2003 John Lampe
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

# Also covers :
# "CVE-1999-1374","CVE-2001-1283","CVE-2001-0076","CVE-2002-0710","CVE-2001-1100","CVE-2002-0346","CVE-2001-0133","CVE-2001-0022","CVE-2001-0420","CVE-2002-0203","CVE-2001-1343"
# "CVE-2002-0917","CVE-2003-0153","CVE-2003-0153","CVE-2000-0423","CVE-1999-1377","CVE-2001-1196","CVE-2002-1526","CVE-2001-0023","CVE-2002-0263","CVE-2002-0263","CVE-2002-0611",
# "CVE-2002-0230","CVE-2000-1131","CVE-2000-0288","CVE-2000-0952","CVE-2001-0180","CVE-2002-1334","CVE-2001-1205","CVE-2000-0977","CVE-2000-0526","CVE-2001-1100","CVE-2000-1023"
# ,"CVE-1999-0937","CVE-2001-0099","CVE-2001-0100","CVE-2001-1212","CVE-2000-1132","CVE-1999-0934","CVE-1999-0935"

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11748");
  script_version("2019-05-10T14:24:23+0000");
  script_tag(name:"last_modification", value:"2019-05-10 14:24:23 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1784, 2177, 2197, 2705, 4211, 4579, 5078);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-1072", "CVE-2002-0749", "CVE-2001-0135", "CVE-2002-0955", "CVE-2001-0562",
                "CVE-2002-0346", "CVE-2000-0923", "CVE-2001-0123");
  script_name("Various dangerous cgi scripts");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2003 John Lampe");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_add_preference(name:"Check all detected CGI directories:", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"Some of the following dangerous CGIs were found.

  By default this script only checks for this CGIs within the /cgi-bin directory. You can change
  this behavior with the script preference to check all detected CGI directories.");

  script_tag(name:"solution", value:"Please take the time to visit cve.mitre.org and check the
  associated CVE ID for each cgi found. If you are running a vulnerable
  version, then delete or upgrade the CGI.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

cgi[0] = "AT-admin.cgi";     cve[0] = "CVE-1999-1072";
cgi[1] = "CSMailto.cgi";     cve[1] = "CVE-2002-0749";
cgi[2] = "UltraBoard.cgi";   cve[2] = "CVE-2001-0135";
cgi[3] = "UltraBoard.pl";    cve[3] = cve[2];
cgi[4] = "YaBB.cgi";         cve[4] = "CVE-2002-0955";
cgi[5] = "a1disp4.cgi";      cve[5] = "CVE-2001-0562";
cgi[6] = "alert.cgi";        cve[6] = "CVE-2002-0346";
cgi[7] = "authenticate.cgi"; cve[7] = "CVE-2000-0923";
cgi[8] = "bbs_forum.cgi";    cve[8] = "CVE-2001-0123";
cgi[9] = "bnbform.cgi";      cve[9] = "CVE-1999-0937";
cgi[10] = "bsguest.cgi";     cve[10] = "CVE-2001-0099";
cgi[11] = "bslist.cgi";      cve[11] = "CVE-2001-0100";
cgi[12] = "catgy.cgi";       cve[12] = "CVE-2001-1212";
cgi[13] = "cgforum.cgi";     cve[13] = "CVE-2000-1132";
cgi[14] = "classifieds.cgi"; cve[14] = "CVE-1999-0934";
cgi[15] = "csPassword.cgi";  cve[15] = "CVE-2002-0917";
cgi[16] = "cvsview2.cgi"  ;  cve[16] = "CVE-2003-0153";
cgi[17] = "cvslog.cgi";      cve[17] = cve[16];
cgi[18] = "multidiff.cgi";   cve[18] = "CVE-2003-0153";
cgi[19] = "dnewsweb.cgi";    cve[19] = "CVE-2000-0423";
cgi[20] = "download.cgi";    cve[20] = "CVE-1999-1377";
cgi[21] = "edit_action.cgi"; cve[21] = "CVE-2001-1196";
cgi[22] = "emumail.cgi";     cve[22] = "CVE-2002-1526";
cgi[23] = "everythingform.cgi"; cve[23] = "CVE-2001-0023";
cgi[24] = "ezadmin.cgi";     cve[24] = "CVE-2002-0263";
cgi[25] = "ezboard.cgi";     cve[25] = "CVE-2002-0263";
cgi[26] = "ezman.cgi";       cve[26] = cve[25];
cgi[27] = "ezadmin.cgi";     cve[27] = cve[25];
cgi[28] = "FileSeek.cgi";    cve[28] = "CVE-2002-0611";
cgi[29] = "fom.cgi";         cve[29] = "CVE-2002-0230";
cgi[30] = "gbook.cgi";       cve[30] = "CVE-2000-1131";
cgi[31] = "getdoc.cgi";      cve[31] = "CVE-2000-0288";
cgi[32] = "global.cgi";      cve[32] = "CVE-2000-0952";
cgi[33] = "guestserver.cgi"; cve[33] = "CVE-2001-0180";
cgi[34] = "imageFolio.cgi";  cve[34] = "CVE-2002-1334";
cgi[35] = "lastlines.cgi";   cve[35] = "CVE-2001-1205";
cgi[36] = "mailfile.cgi";    cve[36] = "CVE-2000-0977";
cgi[37] = "mailview.cgi";    cve[37] = "CVE-2000-0526";
cgi[38] = "sendmessage.cgi"; cve[38] = "CVE-2001-1100";
cgi[39] = "nsManager.cgi";   cve[39] = "CVE-2000-1023";
cgi[40] = "perlshop.cgi";    cve[40] = "CVE-1999-1374";
cgi[41] = "readmail.cgi";    cve[41] = "CVE-2001-1283";
cgi[42] = "printmail.cgi";   cve[42] = cve[41];
cgi[43] = "register.cgi";    cve[43] = "CVE-2001-0076";
cgi[44] = "sendform.cgi";    cve[44] = "CVE-2002-0710";
cgi[45] = "sendmessage.cgi"; cve[45] = "CVE-2001-1100";
cgi[46] = "service.cgi";     cve[46] = "CVE-2002-0346";
cgi[47] = "setpasswd.cgi";   cve[47] = "CVE-2001-0133";
cgi[48] = "simplestmail.cgi"; cve[48] = "CVE-2001-0022";
cgi[49] = "simplestguest.cgi"; cve[49] = cve[48];
cgi[50] = "talkback.cgi";    cve[50] = "CVE-2001-0420";
cgi[51] = "ttawebtop.cgi";   cve[51] = "CVE-2002-0203";
cgi[52] = "ws_mail.cgi";     cve[52] = "CVE-2001-1343";
cgi[53] = "survey.cgi";      cve[53] = "CVE-1999-0936";
cgi[54] = "rxgoogle.cgi";    cve[54] = "CVE-2004-0251";
cgi[55] = "ShellExample.cgi"; cve[55] = "CVE-2004-0696";
cgi[56] = "Web_Store.cgi";   cve[56] = "CVE-2004-0734";
cgi[57] = "csFAQ.cgi";      cve[57] = "CVE-2004-0665";

check_kb_cgi_dirs = script_get_preference( "Check all detected CGI directories:" );

report = string( "The following dangerous CGI scripts were found", "\n\n" );

port = get_http_port( default:80 );

if( check_kb_cgi_dirs == "yes" ) {
  dirs = make_list_unique( "/", "/scripts", "/cgi-bin", cgi_dirs( port:port ) );
} else {
  dirs = make_list( "/cgi-bin" );
}

flag = FALSE;

for( i = 0; cgi[i]; i++ ) {

  foreach dir( dirs ) {

    if( dir == "/" ) dir = "";
    url = dir + "/" + cgi[i];

    if( is_cgi_installed_ka( item:url, port:port ) ) {
      flag = TRUE;
      vuln_url = report_vuln_url( url:url, port:port, url_only:TRUE );
      report += vuln_url + " (" + cve[i] + ')\n';
    }
  }
}

if( flag ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
