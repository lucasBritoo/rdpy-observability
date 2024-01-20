FROM python:3.11

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev


# RUN apt-get update -y && apt-get install python-qt5 -y

COPY requirements/ requirements

RUN pip install -r requirements/dev.txt

COPY . . 

# RUN pip install zope-interface==6.0
# RUN pip install --upgrade setuptools
# RUN python setup.py install

# CMD ["rdpy-rdpclient.py" [-u username] [-p password] [-d domain] [-r rss_ouput_file] [...] XXX.XXX.XXX.XXX[:3389]]