# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

global_var wordpress_themes_info;

# nb:
# - The format is: "[STYLE_URL]", "[NAME]#---#[DETECTION PATTERN]#---#[VERSION REGEX]#---#[CPE]#--#[THEME URL (optional)]"
# - To make sure that we're not using two or more entries for the same file in this array (When e.g.
#   having two entries the foreach(keys()) loop in the detection VT would iterate over both items
#   but the infos variable in both iterations would only include the info from one of both entries
#   two times) we can use something like e.g. the following:
#   egrep -o '^  "[^"]+",' wordpress_themes.inc | sort | uniq -d
#
wordpress_themes_info = make_array(
  "activello/style.css", "colorlib Activello#---#Theme Name: Activello#---#Version: ([0-9.]+)#---#cpe:/a:colorlib:activello#---#https://colorlib.com/wp/themes/activello",
  "affluent/style.css", "CPOThemes Affluent#---#Theme Name:Affluent#---#Version:([0-9.]+)#---#cpe:/a:cpothemes:affluent#---#https://cpothemes.com/theme/affluent",
  "allegiant/style.css", "CPOThemes Allegiant#---#Theme Name:Allegiant#---#Version:([0-9.]+)#---#cpe:/a:cpothemes:allegiant#---#https://cpothemes.com/theme/allegiant",
  "antreas/style.css", "MachoThemes Antreas#---#Author: MachoThemes#---#Version: ([0-9.]+)#---#cpe:/a:machothemes:antreas",
  "bonkers/style.css", "colorlib Bonkers#---#Theme Name: Bonkers#---#Version: ([0-9.]+)#---#cpe:/a:colorlib:bonkers#---#https://colorlib.com/wp/themes/bonkers",
  "brilliance/style.css", "CPOThemes Brilliance#---#Theme Name:Brilliance#---#Version:([0-9.]+)#---#cpe:/a:cpothemes:brilliance#---#https://cpothemes.com/theme/brilliance",
  "clockstone/style.css", "CMSMasters Clockstone#---#Theme Name: Clockstone#---#Version: ([0-9.]+)#---#cpe:/a:cmsmasters:clockstone#---#http://clockstone.cmsmasters.net/",
  "designfolio/style.css", "PressCoders Designfolio#---#Theme Name: Designfolio#---#Version: ([0-9.]+)#---#cpe:/a:presscoders:designfolio",
  "DesignFolio-Plus/style.css", "UpThemes DesignFolio Plus#---#Theme Name: DesignFolio+#---#Version: ([0-9.]+)#---#cpe:/a:upthemes:designfolio-plus#---#https://github.com/UpThemes/DesignFolio-Plus",
  "Divi/style.css", "Elegant Themes Divi#---#Theme Name: Divi#---#Version: ([0-9.]+)#---#cpe:/a:elegantthemes:divi#---#https://www.elegantthemes.com/gallery/divi/",
  # nb: Seems to differ depending on the version or similar
  "enfold/style.css", "Enfold Theme#---#Theme Name: Enfold#---#Version: ([0-9.]+)#---#cpe:/a:kriesi:enfold#---#https://enfoldtheme.info/",
  "enfoldtheme/style.css", "Enfold Theme#---#Theme Name: Enfold#---#Version: ([0-9.]+)#---#cpe:/a:kriesi:enfold#---#https://enfoldtheme.info/",
  "Extra/style.css", "Elegant Themes Extra#---#Theme Name: Extra#---#Version: ([0-9.]+)#---#cpe:/a:elegantthemes:extra#---#https://www.elegantthemes.com/gallery/extra/",
  "flexolio/style.css", "Quarterpixel Flexolio#---#Theme Name: Flexolio#---#Version: ([0-9.]+)#---#cpe:/a:quarterpixel:flexolio",
  "illdy/style.css", "colorlib Illdy#---#Theme Name: Illdy#---#Version: ([0-9.]+)#---#cpe:/a:colorlib:illdy#---#https://colorlib.com/wp/themes/illdy",
  "iloveit/style.css", "CosmoThemes I Love It#---#CosmoThemes#---#Version: ([0-9.]+)#---#cpe:/a:cosmothemes:iloveit#---#https://cosmothemes.com/i-love-it/",
  "medzone-lite/style.css", "MachoThemes MedZone Lite#---#Author: MachoThemes#---#Version: ([0-9.]+)#---#cpe:/a:machothemes:medzone-lite#---#https://www.machothemes.com/medzone-lite/",
  "method/style.css", "Mysitemyway Method#---#Author: Mysitemyway#---#Version: ([0-9.]+)#---#cpe:/a:mysitemyway:method",
  "method/style.css", "BackStop Themes Method#---#Author: BackStop Themes#---#Version: ([0-9.]+)#---#cpe:/a:backstopthemes:method#---#https://backstopthemes.com",
  "naturemag-lite/style.css", "MachoThemes NatureMag-Lite#---#Author: Macho Themes#---#Version: ([0-9.]+)#---#cpe:/a:machothemes:naturemag-lite",
  "Newsmag/style.css", "MachoThemes Newsmag#---#Author: MachoThemes#---#Version: ([0-9.]+)#---#cpe:/a:machothemes:newsmag#---#https://www.machothemes.com/newsmag-lite/",
  "newspaper-x/style.css", "colorlib Newspaper X#---#Theme Name: Newspaper X#---#Version: ([0-9.]+)#---#cpe:/a:colorlib:newspaper-x#---#https://colorlib.com/wp/themes/newspaper-x",
  "mTheme-Unus/style.css", "mTheme-Unus#---#Theme Name: mTheme-Unus#---#Version: ([0-9.]+)#---#cpe:/a:fabrix:mtheme-unus#---#http://fabrix.net/",
  "photocrati-theme/style.css", "Photocrati Theme#---#Theme Name: Photocrati Theme#---#Version: ([0-9.]+)#---#cpe:/a:photocrati:photocrati-theme#---#http://www.photocrati.com/",
  "pixova-lite/style.css", "colorlib Pixova Lite#---#Theme Name: Pixova Lite#---#Version: ([0-9.]+)#---#cpe:/a:colorlib:pixova-lite#---#https://colorlib.com/wp/themes/pixova-lite",
  "regina-lite/style.css", "MachoThemes Regina Lite#---#Author: MachoThemes#---#Version: ([0-9.]+)#---#cpe:/a:machothemes:regina-lite#---#https://www.machothemes.com/regina-lite/",
  "shapely/style.css", "colorlib Shapely#---#Theme Name: Shapely#---#Version: ([0-9.]+)#---#cpe:/a:colorlib:shapely#---#https://colorlib.com/wp/themes/shapely",
  "transcend/style.css", "CPOThemes Transcend#---#Theme Name:Transcend#---#Version:([0-9.]+)#---#cpe:/a:cpothemes:transcend#---#https://cpothemes.com/theme/transcend"
);
