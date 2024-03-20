CXX = g++
CXXFLAGS = -std=c++11 -Wall

# Liste des fichiers source
SRCS = main.cpp
HEADERS = block.hpp

# Générer les noms des fichiers objets à partir des fichiers sources
OBJS = $(SRCS:.cpp=.o)

# Nom du programme final
TARGET = monProgramme

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(TARGET)

%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
