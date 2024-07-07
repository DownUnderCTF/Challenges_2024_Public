<script>
</script>

<template>
      <v-navigation-drawer
        expand-on-hover
        rail
      >
        <v-list>
          <v-list-item
            prepend-avatar="https://randomuser.me/api/portraits/women/85.jpg"
            subtitle="sandra_a88@gmailcom"
            title="Sandra Adams"
          ></v-list-item>
        </v-list>

        <v-divider></v-divider>

        <v-list density="compact" nav>
          <RouterLink to="/" style="text-decoration: none; color: inherit;"><v-list-item prepend-icon="mdi-folder" title="My Files" value="myfiles"></v-list-item></RouterLink>
          <RouterLink to="/" style="text-decoration: none; color: inherit;"><v-list-item prepend-icon="mdi-account-multiple" title="Shared with me" value="shared"></v-list-item></RouterLink>
          <RouterLink to="/" style="text-decoration: none; color: inherit;"><v-list-item prepend-icon="mdi-star" title="Starred" value="starred"></v-list-item></RouterLink>
        </v-list>
      </v-navigation-drawer>
</template>