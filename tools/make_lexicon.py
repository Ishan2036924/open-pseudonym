"""Adds the detection word lists to data/pools.json: given names, places, holidays and a few site lists.

These lists let the rules find what has no cue around it ("I met Priya", "she lives in Boise") and keep the meaning
of what they change ("a city in Idaho", a holiday that keeps its date). Everything here is written for this project
from common knowledge; nothing is copied from a licensed dataset.

Run it, then tools/make_patterns.py (which builds regexes from these lists), then tools/sync_data.py.
"""

import json
from pathlib import Path

POOLS = Path(__file__).resolve().parent.parent / "data" / "pools.json"


def words(s: str) -> list[str]:
    return s.split()


# Given names by gender: f, m, or n when the name is common for anyone. Spread across many cultures on purpose:
# a rule that only knows English names protects some people much better than others.
GIVEN = {
    "f": words("""
        Adele Adriana Agnes Aileen Alana Alice Alicia Alina Alison Allison Alyssa Anastasia Angelina Anita Ann Anne
        Annette Annie Antonia Ariana Arielle Audrey Beatrice Becky Belinda Bernadette Beth Bethany Bonnie Brianna
        Bridget Caitlin Camille Candace Cara Carla Carmen Caroline Cassandra Catherine Cecilia Celeste Charlene Christa
        Cindy Claire Claudia Colleen Connie Courtney Danielle Daphne Darlene Delia Delilah Dolores Dominique Doris Edith
        Eileen Elaine Eleanor Elisa Elise Eliza Ellen Eloise Elsa Elsie Emilia Erica Erin Estelle Eunice Eva Fiona
        Frances Francesca Gabrielle Gemma Geraldine Gillian Gina Giselle Gwen Gwendolyn Harriet Hazel Heidi Helen Hilda
        Imogen Irene Isabel Isla Ivana Jasmine Jeanne Jenna Jenny Jill Joanna Jocelyn Johanna Josephine Josie Julianne
        Juliet Justine Karina Kate Katie Katrina Kristen Kristin Laura Lauren Leah Leona Leslie Lillian Lindsay Lisa
        Lois Loretta Lorraine Louise Lucy Lydia Lynn Mabel Madeline Maggie Mandy Marcia Margaret Margot Maria Marie
        Marilyn Marion Marissa Martha Maureen Megan Melanie Melissa Meredith Michelle Miranda Miriam Molly Monica Nancy
        Naomi Natalie Natasha Nicole Nora Olivia Pamela Paula Pauline Penelope Phoebe Phyllis Priscilla Rachel Rebecca
        Renee Rita Roberta Rosalind Rosemary Ruth Sabrina Samantha Sandra Sara Sarah Shannon Sharon Sheila Shirley
        Simone Sophia Sophie Stella Stephanie Susan Suzanne Sylvia Tamara Tanya Teresa Theresa Tiffany Tina Tracy Ursula
        Vanessa Vera Veronica Viola Vivian Wanda Wendy Whitney Yvonne Zoe
        Alejandra Carolina Catalina Consuelo Cristina Guadalupe Isabela Jimena Leticia Lorena Luisa Manuela Marcela
        Marisol Natalia Paola Rocío Valentina Rafaela Larissa Bruna Fabiana Alessia Antonella Chiara Giulia Amélie
        Aurélie Céline Élodie Hélène Nathalie Sylvie Anke Birgit Gisela Heike Sabine Stefanie Astrid Linnea Sigrid
        Ekaterina Irina Katarzyna Magdalena Oksana Svetlana Tatiana Yulia Zofia
        Aditi Ananya Anjali Aruna Bhavna Deepa Devika Divya Geeta Isha Jaya Kavya Lakshmi Meena Meera Nandini Neha Nisha
        Pooja Priya Priyanka Rekha Sanjana Shreya Shruti Sneha Sunita Swati Tanvi Zoya Ayesha Sadia Zainab Farzana
        Parisa Shirin Amina Aya Dalia Farah Laila Leila Mariam Maryam Rania Reem Salma Yasmin Zeynep Elif Ayşe Ece
        Fang Hui Jing Ling Mei Xiaoyu Jiayi Seo-yeon Ha-eun Eun-ji Yui Aoi Haruka Misaki Mariko Naoko Tomoko Yoshiko
        Yumi Riko Linh Huong Thao Trang Phuong Hoa
        Abena Adaeze Adwoa Akosua Chidinma Chioma Ebele Folake Funmilayo Ifeoma Lerato Ngozi Nkechi Zanele Zodwa Selam
        Tsion Wanjiru Wambui Achieng Njeri Halima Fatoumata Aminata Noa Yael Tamar Shira Rivka
        María Sofía Lucía Inés Mónica Liz Jen Jess Meg Becca Abby Pam Deb Barb Cathy Kathy Lizzie Ellie Millie Tilly
        Nell Bea Fran Peggy Polly Dolly Sally Patty
        """),
    "m": words("""
        Abraham Adrian Alfred Allen Alvin Andre Andreas Andy Angelo Antonio Archie Arnold Barry Bernard Brendan Brett
        Byron Calvin Cameron Cecil Cedric Chris Clarence Clayton Clifford Clint Colin Conor Connor Craig Curtis
        Damian Damon Darren Darius Dave Derek Desmond Dominic Donovan Duncan Dustin Edgar Edmund Eduardo Edwin Elliot
        Elliott Emmanuel Ernest Evan Fabian Fernando Floyd Francis Francisco Franklin Fred Frederick Gareth Gavin
        Geoffrey Gerard Gilbert Gordon Graham Harrison Harvey Hector Herbert Howard Ian Isaac Jake Jared Jasper Jerome
        Jonah Jorge Julian Julius Kelvin Kurt Larry Lawrence Leo Leon Leonard Lewis Liam Lionel Lorenzo Louis Lucas Luke
        Malcolm Manuel Marcus Mario Martin Matthew Maurice Melvin Michael Mitchell Morris Nathan Neil Nelson Nicholas
        Nigel Noah Norman Oliver Omar Oscar Owen Patrick Paul Peter Philip Phillip Quentin Ralph Randall Raymond
        Reginald Ricardo Richard Robert Roberto Rodney Roger Roland Ronald Ross Roy Russell Ryan Samuel Scott Sean
        Sebastian Sergio Seth Shane Simon Spencer Stanley Stefan Stephen Steven Stuart Theodore Thomas Timothy Tobias
        Todd Travis Trevor Tristan Troy Victor Vincent Walter Warren Wayne Wesley William Xavier Zachary
        Alejandro Alfonso Álvaro Andrés Emilio Enrique Esteban Federico Guillermo Gustavo Ignacio Javier Joaquín José
        Juan Julio Luis Martín Miguel Pablo Pedro Rafael Ramón Raúl Rodrigo João Thiago Gonçalo Leandro Alessandro
        Giorgio Giuseppe Luca Marco Matteo Paolo Riccardo Stefano Antoine Benoît Clément Étienne François Julien Mathieu
        Pierre Sébastien Thierry Yves Dieter Friedrich Günter Jürgen Klaus Lukas Markus Matthias Uwe Wolfgang Anders
        Björn Bjorn Erik Lars Magnus Mikael Nils Søren Soren Sven Aleksandr Andrei Bogdan Łukasz Lukasz Marek Mikhail
        Nikolai Pavel Piotr Sergei Vladimir
        Aarav Aditya Akash Akshay Amitabh Anand Ankit Anil Anupam Arun Ashok Deepak Dinesh Gaurav Harish Karan Mahesh
        Manish Mohan Nikhil Pradeep Prakash Pranav Rahul Rajesh Rakesh Ramesh Ravi Rohan Rohit Sachin Sanjay Sandeep
        Siddharth Sunil Suresh Varun Vijay Vikram Vinod Vishal Bilal Faisal Farhan Hassan Imran Kamran Saad Tariq Usman
        Abdullah Ahmad Bashir Habib Hadi Hussein Ibrahim Jamal Karim Khalid Mahmoud Mohamed Mohammed Muhammad Mustafa
        Nabil Rami Samir Tarek Yusuf Youssef Zaid Mehmet Emre Burak Cem Kerem Murat Ömer Serkan Dariush Mehdi Navid Reza
        Qiang Xiaoming Yifan Haoran Min-jun Ji-ho Haruto Takeshi Yuto Sota Akira Daisuke Kaito Ryota Satoshi Shota
        Takumi Kazuki Tuan Hung Dung Hieu Quang Trung Duc
        Adebayo Ayodele Babajide Chidi Chinedu Chukwuemeka Emeka Femi Ikenna Kofi Kwabena Kwame Kwasi Mandla Musa Nnamdi
        Obinna Sipho Thabo Themba Tunde Abebe Kamau Otieno Juma Moussa Ousmane Mamadou Eitan Moshe Yosef Itai Dov Avi
        Sebastián Nicolás Tomás Jesús Germán Iván Dan Tom Tim Jim Ben Nick Mike Matt Steve Rick Ron Tony Jeff Greg Phil
        Pete Ted Ken Josh Zach Nate Gabe Theo Ollie Freddie Alfie Harry Danny Johnny Jimmy Tommy Eddie Ricky Joey Benny
        Lenny Sammy Gus Hank Hal Ned Sid Stan Walt Wes Zeke
        """),
    "n": words("""
        Quinn Reese Sasha Charlie Frankie Kai Nico Noor Ari Remy Rory Shay Toby Jody Kerry Peyton Logan Dakota Kiran
        Chandra Krishna Madhu Wei Ming Jun Yan Xin Lei Hao Yuki Ren Hana Minh Anh Thanh Thu Bao Hai Lan Khanh Kehinde
        Uchenna Tendai Chad Oluwaseun Oluwatobi Baraka Ariel Lior Oren Deniz Yuxuan Zihan Jiwoo Ji-woo Minjun
        Hương Thảo Tuấn Hùng Dũng Hiếu Khánh Phương Bảo Đức Hải An Thu
        """),
}

# Names that are also everyday words, months or titles. They stay out of the cue-free rule ("Will you...", "Mark the
# date", "May 5"), but are still caught after a cue ("Hi Will") and still count for gender.
AMBIGUOUS = set(words("""
    Will Mark Bill Rob Bob May June April August Jun Jan Grace Hope Faith Joy Rose Iris Ivy Lily Daisy Holly Pearl Ruby
    Amber Crystal Dawn Eve Summer Autumn Sunny Sky Skye Sage Rain River Stone Hunter Chase Gene Pat Ray Max Art Guy
    Earl Duke King Prince Major Rich Sterling Price Young Long Don Dean Mason Carter Cooper Taylor Archer Baker Parker
    Porter Tucker Wade Drew Sue Jean Lane Dale Glen Brook Brooke Cliff Heath Forrest Penny Candy Ginger Honey Angel
    Precious Destiny Trinity Unity Harmony Melody Star Storm Nova Jade Ace Rocky Sandy Rusty Buddy Mercy Patience
    Charity Justice Royal Gay Dick Randy Frank Jack Bishop Page Rex Grant Lance Miles Dev Van Nam Bo Can Jay Kay Al Ed
    Jo Li Yi An Di Om Thu Sakura Violet Virginia Georgia Carolina Mercedes India Kenya Israel
"""))

# Genders for the everyday-word names above that are common given names, so "Hi Will" gets a first-name stand-in.
AMBIGUOUS_GENDER = {
    "f": words("May June April Grace Hope Faith Joy Rose Iris Ivy Lily Daisy Holly Ruby Amber Dawn Eve Penny Jade Kay "
               "Jo Sue Jean Brooke Skye Summer Autumn Violet Virginia Georgia Carolina Mercedes Sakura"),
    "m": words("Will Mark Bill Rob Bob Max Ray Jack Frank Grant Jay Ed Al Dean Don Wade Gene Mason Carter Hunter Chase "
               "Lance Miles Dev Earl Guy Art Randy"),
    "n": words("Drew Pat Taylor Parker Sandy Angel Sunny"),
}

# Surnames that come first in East Asian and Vietnamese names ("Zhang Wei", "Nguyễn Văn An"). A known given name must
# follow. The ones that are also English words ("He", "Do", "Park") are only trusted before an unambiguous given name.
FAMILY_FIRST = words("""
    Wang Zhang Liu Chen Yang Huang Zhao Wu Zhou Xu Zhu Guo Luo Gao Choi Jung Kang Cho Yoon Jang Lim Shin Nguyen Nguyễn
    Tran Trần Pham Phạm Hoang Hoàng Huỳnh Phan Vu Võ Dang Đặng Bui Bùi Đỗ Hồ Lê Ngo Ngô Duong Dương Ly Lý Tanaka Sato
    Suzuki Takahashi Watanabe Ito Yamamoto Nakamura Kobayashi
""")
FAMILY_FIRST_WORDS = words("He Do Ho Le Ma Sun Hu Li Lee Kim Park Han Lin")
# Vietnamese middle names that sit between the family and given name
MIDDLE = words("Văn Thị Van Thi")


# Places, with what a coarser description needs: (kind, the place it sits in).
COUNTRIES = {
    "Africa": """Algeria Angola Benin Botswana Burkina_Faso Burundi Cameroon Cape_Verde Central_African_Republic Chad
        Comoros Congo Democratic_Republic_of_the_Congo Djibouti Egypt Equatorial_Guinea Eritrea Eswatini Ethiopia Gabon
        Gambia Ghana Guinea Guinea-Bissau Ivory_Coast Kenya Lesotho Liberia Libya Madagascar Malawi Mali Mauritania
        Mauritius Morocco Mozambique Namibia Niger Nigeria Rwanda Senegal Seychelles Sierra_Leone Somalia South_Africa
        South_Sudan Sudan Tanzania Togo Tunisia Uganda Zambia Zimbabwe""",
    "Asia": """Hong_Kong Macau Afghanistan Armenia Azerbaijan Bahrain Bangladesh Bhutan Brunei Cambodia China Cyprus Georgia India
        Indonesia Iran Iraq Israel Japan Jordan Kazakhstan Kuwait Kyrgyzstan Laos Lebanon Malaysia Maldives Mongolia
        Myanmar Nepal North_Korea Oman Pakistan Philippines Qatar Saudi_Arabia Singapore South_Korea Sri_Lanka Syria
        Taiwan Tajikistan Thailand Timor-Leste Turkey Turkmenistan United_Arab_Emirates UAE Uzbekistan Vietnam Yemen""",
    "Europe": """Albania Andorra Austria Belarus Belgium Bosnia_and_Herzegovina Bulgaria Croatia Czechia
        Czech_Republic Denmark England Estonia Finland France Germany Greece Hungary Iceland Ireland Italy Kosovo Latvia
        Liechtenstein Lithuania Luxembourg Malta Moldova Monaco Montenegro Netherlands Holland North_Macedonia
        Northern_Ireland Norway Poland Portugal Romania Russia San_Marino Scotland Serbia Slovakia Slovenia Spain Sweden
        Switzerland Ukraine United_Kingdom UK Wales""",
    "the Americas": """Argentina Bahamas Barbados Belize Bolivia Brazil Canada Chile Colombia Costa_Rica Cuba
        Dominican_Republic Ecuador El_Salvador Guatemala Guyana Haiti Honduras Jamaica Mexico Nicaragua Panama Paraguay
        Peru Puerto_Rico Suriname Trinidad_and_Tobago United_States USA Uruguay Venezuela""",
    "Oceania": "Australia Fiji New_Zealand Papua_New_Guinea Samoa Tonga Vanuatu Solomon_Islands",
}
US_STATES = """Alabama Alaska Arizona Arkansas California Colorado Connecticut Delaware Florida Georgia Hawaii Idaho
    Illinois Indiana Iowa Kansas Kentucky Louisiana Maine Maryland Massachusetts Michigan Minnesota Mississippi
    Missouri Montana Nebraska Nevada New_Hampshire New_Jersey New_Mexico New_York North_Carolina North_Dakota Ohio
    Oklahoma Oregon Pennsylvania Rhode_Island South_Carolina South_Dakota Tennessee Texas Utah Vermont Virginia
    Washington West_Virginia Wisconsin Wyoming"""
REGIONS = {
    "Canada": """Alberta British_Columbia Manitoba New_Brunswick Newfoundland_and_Labrador Nova_Scotia Ontario
        Prince_Edward_Island Quebec Saskatchewan""",
    "Australia": "New_South_Wales Queensland South_Australia Tasmania Western_Australia",
    "India": """Maharashtra Karnataka Tamil_Nadu Kerala Gujarat Rajasthan Punjab Uttar_Pradesh West_Bengal Telangana
        Andhra_Pradesh Bihar Odisha""",
}
CITIES = {
    "Alabama": "Birmingham Montgomery Huntsville Mobile", "Alaska": "Anchorage Juneau Fairbanks",
    "Arizona": "Phoenix Tucson Mesa Scottsdale Tempe Flagstaff", "Arkansas": "Little_Rock Fayetteville",
    "California": """Los_Angeles San_Francisco San_Diego San_Jose Sacramento Oakland Fresno Long_Beach Berkeley
        Palo_Alto Santa_Monica Pasadena Irvine Anaheim Riverside Santa_Barbara Mountain_View Sunnyvale Cupertino""",
    "Colorado": "Denver Boulder Colorado_Springs Aurora Fort_Collins",
    "Connecticut": "Hartford New_Haven Stamford Bridgeport", "Delaware": "Wilmington Dover",
    "Florida": "Miami Orlando Tampa Jacksonville Tallahassee Fort_Lauderdale St._Petersburg Gainesville",
    "Georgia": "Atlanta Savannah Augusta Athens", "Hawaii": "Honolulu Hilo", "Idaho": "Boise Idaho_Falls Pocatello",
    "Illinois": "Chicago Springfield Naperville Evanston Peoria", "Indiana": "Indianapolis Fort_Wayne Bloomington",
    "Iowa": "Des_Moines Cedar_Rapids Iowa_City", "Kansas": "Wichita Topeka Kansas_City Lawrence",
    "Kentucky": "Louisville Lexington Frankfort", "Louisiana": "New_Orleans Baton_Rouge Shreveport",
    "Maine": "Portland Augusta Bangor", "Maryland": "Baltimore Annapolis Bethesda Rockville",
    "Massachusetts": "Boston Cambridge Worcester Somerville Lowell Quincy Newton Brookline Salem",
    "Michigan": "Detroit Ann_Arbor Grand_Rapids Lansing", "Minnesota": "Minneapolis St._Paul Duluth Rochester",
    "Mississippi": "Jackson Biloxi", "Missouri": "St._Louis Kansas_City Jefferson_City",
    "Montana": "Missoula Billings Bozeman Helena", "Nebraska": "Omaha Lincoln", "Nevada": "Las_Vegas Reno Carson_City",
    "New Hampshire": "Manchester Concord Nashua", "New Jersey": "Newark Jersey_City Trenton Princeton Hoboken",
    "New Mexico": "Albuquerque Santa_Fe Las_Cruces",
    "New York": "New_York_City Brooklyn Manhattan Buffalo Albany Rochester Syracuse Ithaca Queens Bronx",
    "North Carolina": "Charlotte Raleigh Durham Chapel_Hill Greensboro Asheville", "North Dakota": "Fargo Bismarck",
    "Ohio": "Columbus Cleveland Cincinnati Toledo Akron Dayton", "Oklahoma": "Oklahoma_City Tulsa Norman",
    "Oregon": "Portland Eugene Salem Bend", "Pennsylvania": "Philadelphia Pittsburgh Harrisburg Allentown Erie",
    "Rhode Island": "Providence Newport", "South Carolina": "Charleston Columbia Greenville",
    "South Dakota": "Sioux_Falls Pierre Rapid_City", "Tennessee": "Nashville Memphis Knoxville Chattanooga",
    "Texas": "Houston Dallas Austin San_Antonio Fort_Worth El_Paso Plano Arlington Corpus_Christi",
    "Utah": "Salt_Lake_City Provo Ogden", "Vermont": "Burlington Montpelier",
    "Virginia": "Richmond Virginia_Beach Norfolk Arlington Alexandria Charlottesville",
    "Washington": "Seattle Spokane Tacoma Olympia Bellevue Redmond", "West Virginia": "Charleston Morgantown",
    "Wisconsin": "Milwaukee Madison Green_Bay", "Wyoming": "Cheyenne Casper Jackson",
    "the US": "Washington_D.C. Washington,_D.C.",
    "Canada": "Toronto Montreal Vancouver Calgary Ottawa Edmonton Winnipeg Halifax Victoria Regina Quebec_City",
    "Mexico": "Mexico_City Guadalajara Monterrey Tijuana Cancún Cancun Puebla",
    "Brazil": "São_Paulo Sao_Paulo Rio_de_Janeiro Brasília Brasilia Salvador Belo_Horizonte",
    "Argentina": "Buenos_Aires Córdoba Rosario", "Chile": "Santiago Valparaíso", "Colombia": "Bogotá Bogota Medellín Cali",
    "Peru": "Lima Cusco", "England": """London Manchester Birmingham Liverpool Leeds Bristol Oxford Cambridge Brighton
        Sheffield Newcastle Nottingham Leicester York Bath""",
    "Scotland": "Edinburgh Glasgow Aberdeen Dundee", "Wales": "Cardiff Swansea", "Northern Ireland": "Belfast",
    "Ireland": "Dublin Cork Galway", "France": "Paris Lyon Marseille Toulouse Nice Bordeaux Lille Strasbourg Nantes",
    "Germany": "Berlin Munich Hamburg Frankfurt Cologne Stuttgart Düsseldorf Dusseldorf Leipzig Dresden",
    "Spain": "Madrid Barcelona Valencia Seville Bilbao Málaga Malaga", "Portugal": "Lisbon Porto",
    "Italy": "Rome Milan Naples Turin Florence Venice Bologna Genoa", "Netherlands": "Amsterdam Rotterdam The_Hague Utrecht",
    "Belgium": "Brussels Antwerp Ghent", "Switzerland": "Zurich Zürich Geneva Basel Bern Lausanne",
    "Austria": "Vienna Salzburg Graz", "Sweden": "Stockholm Gothenburg Malmö Malmo", "Norway": "Oslo Bergen",
    "Denmark": "Copenhagen Aarhus", "Finland": "Helsinki Tampere", "Poland": "Warsaw Kraków Krakow Gdańsk Wrocław",
    "Czechia": "Prague Brno", "Hungary": "Budapest", "Greece": "Athens Thessaloniki", "Russia": "Moscow Saint_Petersburg",
    "Ukraine": "Kyiv Kiev Lviv Odesa", "Romania": "Bucharest Cluj-Napoca", "Turkey": "Istanbul Ankara Izmir",
    "Israel": "Tel_Aviv Jerusalem Haifa", "Egypt": "Cairo Alexandria", "Nigeria": "Lagos Abuja Ibadan",
    "Kenya": "Nairobi Mombasa", "South Africa": "Johannesburg Cape_Town Durban Pretoria", "Ghana": "Accra Kumasi",
    "Ethiopia": "Addis_Ababa", "Morocco": "Casablanca Marrakesh Rabat", "United Arab Emirates": "Dubai Abu_Dhabi",
    "Saudi Arabia": "Riyadh Jeddah", "Qatar": "Doha", "Pakistan": "Karachi Lahore Islamabad",
    "India": """Mumbai Delhi New_Delhi Bengaluru Bangalore Hyderabad Chennai Kolkata Pune Ahmedabad Jaipur Lucknow
        Kochi Chandigarh Noida Gurugram Gurgaon""",
    "Bangladesh": "Dhaka Chittagong", "Sri Lanka": "Colombo", "Nepal": "Kathmandu",
    "China": "Beijing Shanghai Shenzhen Guangzhou Chengdu Hangzhou Wuhan Xi'an Nanjing", "Hong Kong": "Kowloon",
    "Taiwan": "Taipei Kaohsiung", "Japan": "Tokyo Osaka Kyoto Yokohama Nagoya Sapporo Fukuoka",
    "South Korea": "Seoul Busan Incheon", "Vietnam": "Hanoi Ho_Chi_Minh_City Saigon Da_Nang",
    "Thailand": "Bangkok Chiang_Mai Phuket", "Singapore": "", "Malaysia": "Kuala_Lumpur Penang",
    "Indonesia": "Jakarta Bali Surabaya", "Philippines": "Manila Cebu Quezon_City",
    "Australia": "Sydney Melbourne Brisbane Perth Adelaide Canberra Hobart Darwin",
    "New Zealand": "Auckland Wellington Christchurch",
}
# Place names that are also surnames or everyday words: only trusted after a place cue ("in Jackson"). Places that
# are also given names (Austin, Charlotte, Jordan) are added to this list automatically.
AMBIGUOUS_PLACES = set(words("""
    Washington Lincoln Jackson Houston Dallas Madison Newton Quincy Lawrence Norman Columbus Arlington Richmond
    Rochester Springfield Burlington Greenville Bellevue Portland Manchester Birmingham Newport Charleston Salem Troy
    Concord Providence Independence Bath Reading Nice Mobile Bend Cork Jersey Chad Turkey Aurora Mesa Erie Cali
    Darwin Perth Hilo Casper Athens Alexandria Augusta Helena Columbia Florence Regina Eugene Lima Santiago Salvador
    Bergen Basel Bern Porto Bologna Genoa Pune Kochi Ogden Provo Durham Raleigh Billings Victoria Sydney York Cambridge
    Lansing Wilmington Dover Bristol Newcastle Leicester Augusta Mobile Pierre Cheyenne Frankfort Hartford Oxford
    Wellington
"""))

HOLIDAYS = [
    "Christmas", "Christmas Eve", "Christmas Day", "New Year", "New Year's", "New Year's Day", "New Year's Eve",
    "Thanksgiving", "Easter", "Easter Sunday", "Easter Monday", "Good Friday", "Halloween", "Valentine's Day",
    "Independence Day", "Fourth of July", "Diwali", "Holi", "Eid", "Eid al-Fitr", "Eid al-Adha", "Ramadan", "Hanukkah",
    "Passover", "Rosh Hashanah", "Yom Kippur", "Lunar New Year", "Chinese New Year", "Boxing Day", "Labor Day",
    "Labour Day", "Memorial Day", "Veterans Day", "Mother's Day", "Father's Day", "St. Patrick's Day",
    "Saint Patrick's Day", "Juneteenth", "Kwanzaa", "Canada Day", "Bastille Day", "Australia Day",
    "Martin Luther King Day", "MLK Day", "Presidents' Day", "Presidents Day", "Columbus Day",
    "Indigenous Peoples' Day", "Remembrance Day", "Guy Fawkes Night", "Bonfire Night", "Groundhog Day", "Earth Day",
    "Cinco de Mayo", "Day of the Dead", "Mardi Gras", "Pentecost", "Black Friday", "Cyber Monday",
]
BIRTH_CUES = ["born", "birthday", "birth date", "birthdate", "date of birth", "DOB", "D.O.B."]

# Sites whose path names a person: linkedin.com/in/<person>, github.com/<person>, x.com/<person> ...
PROFILE_HOSTS = words("""
    linkedin.com github.com gitlab.com x.com twitter.com instagram.com facebook.com fb.com tiktok.com threads.net
    medium.com youtube.com reddit.com pinterest.com behance.net dribbble.com t.me wa.me snapchat.com twitch.tv vk.com
    quora.com stackoverflow.com keybase.io bsky.app about.me linktr.ee calendly.com venmo.com paypal.me cash.app
    patreon.com ko-fi.com buymeacoffee.com soundcloud.com flickr.com vimeo.com tumblr.com xing.com weibo.com
    kaggle.com huggingface.co npmjs.com pypi.org substack.com wellfound.com
""")
# Path words on those sites that are structure, not a person.
PROFILE_PATH_WORDS = words("""
    in pub company school u user users profile people channel c status posts p reel reels watch video videos photo
    photos about home feed groups events pages repos repositories tree blob issues pull pulls wiki settings
    followers following likes stars tab activity detail recent-activity overview
""")
# Things that look like @mentions in code and docs but are not people.
CODE_MENTIONS = words("""
    property staticmethod classmethod dataclass abstractmethod cached_property override Override Test Before After
    BeforeEach AfterEach Autowired Component Injectable Input Output Bean Entity Table Column Id Service Controller
    RestController Repository Configuration Value Param param returns return type typedef deprecated see link author
    since version throws example media import keyframes font-face supports page charset namespace layer tailwind
    apply extend mixin include use forward if else each for while function everyone here channel all pytest
    fixture mark patch app router api route get post put delete
""")
# Companies named after people: without this, "Morgan Stanley" would be taken for a person.
ORG_NAMES = [
    "Morgan Stanley", "JPMorgan", "J.P. Morgan", "Goldman Sachs", "Charles Schwab", "Edward Jones", "Raymond James",
    "Ernst & Young", "Johnson & Johnson", "Ben & Jerry's", "Marks & Spencer", "Tim Hortons", "Wells Fargo",
    "Lockheed Martin", "Merrill Lynch", "Dean & DeLuca", "Thomas Cook", "Ralph Lauren", "Calvin Klein",
    "Tommy Hilfiger", "Hugo Boss", "Louis Vuitton", "Christian Dior", "Estée Lauder", "Paul Smith", "Ted Baker",
    "Martha Stewart Living", "Walt Disney", "Charles River", "Henry Schein", "John Deere", "John Lewis",
    "Sherwin-Williams", "Procter & Gamble", "Kellogg's", "Hewlett Packard", "Booz Allen", "Arthur D. Little",
]


def title(s: str) -> str:
    return s.replace("_", " ")


def main() -> None:
    doc = json.loads(POOLS.read_text(encoding="utf-8"))
    gender = dict(doc["name_gender"])
    for g, names in GIVEN.items():
        for n in names:
            gender.setdefault(n.lower(), g)
    for g, names in AMBIGUOUS_GENDER.items():
        for n in names:
            gender.setdefault(n.lower(), g)
    doc["name_gender"] = dict(sorted(gender.items()))
    doc["ambiguous_names"] = sorted(AMBIGUOUS)
    doc["family_first"] = sorted(set(FAMILY_FIRST))
    doc["family_first_words"] = sorted(set(FAMILY_FIRST_WORDS))
    doc["middle_names"] = MIDDLE

    places: dict[str, list[str]] = {}
    for continent, names in COUNTRIES.items():
        for n in names.split():
            places[title(n)] = ["country", continent]
    states = {title(n) for n in US_STATES.split()}
    for n in states:
        places.setdefault(n, ["state", "the US"])
    for country, names in REGIONS.items():
        for n in names.split():
            places.setdefault(title(n), ["region", country])
    city_regions: dict[str, set[str]] = {}
    for region, names in CITIES.items():
        for n in names.split():
            city_regions.setdefault(title(n), set()).add(region)
    for city, regions in sorted(city_regions.items()):
        if city in places:
            continue
        if len(regions) == 1:
            places[city] = ["city", next(iter(regions))]
        else:
            # Portland is in Maine and in Oregon: say only what all of them share
            places[city] = ["city", "the US" if regions <= states else ""]
    places["Georgia"] = ["place", ""]  # a US state and a country: too ambiguous for a region
    given = {n.lower() for n in gender} - {a.lower() for a in AMBIGUOUS}
    ambiguous_places = {p for p in places if p in AMBIGUOUS_PLACES or p.lower() in given}
    doc["places"] = dict(sorted(places.items()))
    doc["ambiguous_places"] = sorted(ambiguous_places)
    doc["holidays"] = HOLIDAYS
    doc["birth_cues"] = BIRTH_CUES
    doc["profile_hosts"] = sorted(set(PROFILE_HOSTS))
    doc["profile_path_words"] = sorted(set(PROFILE_PATH_WORDS))
    doc["code_mentions"] = sorted(set(CODE_MENTIONS))
    doc["org_names"] = ORG_NAMES
    doc["us_state_codes"] = dict(zip(words("""AL AK AZ AR CA CO CT DE FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS
        MO MT NE NV NH NJ NM NY NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY DC"""),
        [title(n) for n in US_STATES.split()] + ["Washington, D.C."]))
    POOLS.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"pools.json: {len(gender)} given names, {len(places)} places, {len(HOLIDAYS)} holidays")


if __name__ == "__main__":
    main()
