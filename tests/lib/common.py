import re
from faker import Faker

faker = Faker()

OBSERVED = {}

def profile():
    """ Returns a unique simple profile
    """
    for i in range(100):
        profile = faker.profile()
        login = profile['username']
        if login not in OBSERVED:
            break
    else:
        raise Exception(f"Unable to create unique profile!")
    OBSERVED[login] = True
    return profile

def job():
    for i in range(100):
        job_name = faker.job()
        if job_name not in OBSERVED:
            break
    else:
        raise Exception(f"Unable to create unique job name!")
    OBSERVED[job_name] = True
    return job_name

def name():
    for i in range(100):
        firstname = re.sub(r"[,()]","",faker.first_name())
        lastname = re.sub(r"[,()]","",faker.last_name())
        name = f"{firstname} {lastname}"
        if name not in OBSERVED:
            break
    else:
        raise Exception(f"Unable to create unique name!")
    OBSERVED[name] = True
    return firstname, lastname, name

def sentence():
    return faker.sentence()
